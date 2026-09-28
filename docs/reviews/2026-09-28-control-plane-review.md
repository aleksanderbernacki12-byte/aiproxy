# Genomgång av Aiproxy Control Plane

Granskad 28 september 2026. Bas: `main`, commit `3fb73a1`. Omfattar `control-plane/` (Next.js-tjänsten, migreringar och skript) samt de delar av Go-dataplanet som avgör hur telemetrikedjan byggs och levereras (`internal/telemetry`).

**Bedömning:** Control Plane är genomgående noggrant byggd. Autentisering, rollkontroll, CSRF-skydd, storleksgränser, signaturverifiering och kvittoverifiering vid extern förankring är korrekt gjorda. Organisationsfiltret finns på varje fråga som granskats. De två allvarliga fynden gäller tjänstens kärnlöfte, att bevisningen är manipuleringssäker och verifierbar över tid. En enda förlorad länk gör all framtida telemetri för nyckeln permanent "komprometterad". Lagrade events kan dessutom ändras i databasen utan att något upptäcker det.

**Verifiering**

- GitHubs Control Plane-jobb (lint, enhetstester, PostgreSQL-integration och återställning, produktionsbygge, typkontroll, Playwright) lyckades på `3fb73a1`.
- Detta är kodgranskning. Fynd 1 och 2 är spårade i koden men inte reproducerade med nya tester. Kodvägen för kedjebrott (`COMPROMISED_CHAIN`) saknar test helt.

**Prioritet P1**

**1. Telemetrikedjan återhämtar sig aldrig efter ett brott.**

När ingen buffrad händelse förlänger kedjans huvud och den äldsta har väntat längre än omordningsfönstret klassas den som `COMPROMISED_CHAIN`. Kedjans huvud (`latestEventHash`) flyttas dock bara fram för `VERIFIED`. Nästa händelse pekar på den komprometterade händelsens hash, som aldrig blir huvud, och klassas därför också som komprometterad. Från första luckan blir alltså varje korrekt signerad händelse för den nyckeln komprometterad för alltid, tills nyckeln byts.

Det räcker med en driftshändelse för att utlösa detta. Dataplanet läser signeringsnyckeln från en egen fil (`PrivateKeyPath`), medan kedjans tillstånd (`previous_event_hash`) ligger i kö-databasen (`DatabasePath`). Om kö-databasen försvinner men nyckeln finns kvar börjar kedjan om från `""` med samma `key_id`. Det kan hända vid ny container utan volym för kön, flytt till ny värd eller en borttagen korrupt fil.

Följdeffekt: gallringen tar bara bort `VERIFIED`-händelser. Efter ett brott slutar därför gallringspolicyn tyst att gälla för nyckeln, och data sparas utan tidsgräns i strid med den konfigurerade policyn.

Förslag:

- Behandla ett brott som en uttrycklig diskontinuitet och inte som ett permanent tillstånd. Spara en gap-post med förväntad och mottagen `previous_event_hash`, och markera den första händelsen efter luckan.
- Starta sedan ett nytt kedjesegment vars huvud kan flyttas fram igen. Ett genesis-event (`previous_event_hash = ""`) mot ett befintligt huvud bör klassas som "kedjan återstartad" och inte som manipulation.
- Låt rapport och dashboard visa antal luckor och segment. Låt gallringen omfatta verifierade segment.
- I dataplanet: lagra kedjans tillstånd tillsammans med nyckeln, eller vägra starta med befintlig nyckel och tom kö utan ett uttryckligt val.
- Lägg till tester för lucka, genesis-omstart och återhämtning.

Kod: [processKeyChain](../../control-plane/src/lib/telemetry/worker.ts), [findExtendingEventIndex](../../control-plane/src/lib/telemetry/ordering.ts), [persist](../../internal/telemetry/store.go).

*Åtgärdat 2026-09-28:* en lucka flaggas en gång och kedjan fortsätter därefter; sena events flaggas utan att dela kedjan; gallringen omfattar flaggade luckor. Se [specen](../superpowers/specs/2026-09-28-telemetry-chain-recovery-design.md). Dataplanets del (kedjetillstånd tillsammans med nyckeln) är inte ändrad, eftersom Control Plane nu hanterar en omstart.

**2. Lagrad bevisning kan ändras utan att det upptäcks.**

`security_audit_events` och `telemetry_tombstones` skyddas av triggers mot ändring. `telemetry_events`, `compliance_reports`, `telemetry_merkle_checkpoints` och `telemetry_chain_heads` saknar sådant skydd. Signatur och kedja kontrolleras bara vid mottagningen. Ingen kod verifierar lagrade events mot de förankrade kedjehuvudena i efterhand. Dashboardens siffror och de förseglade rapporterna räknas fram ur kolumner som går att ändra, till exempel `compliance_flags` och `status`. Den som har skrivrätt i databasen kan alltså ändra en händelse från `pii_detected: true` till `false`. Nästa rapport blir då signerad och förseglad med den ändrade siffran, trots att den lagrade signaturen inte längre stämmer. Det är just den aktören som ett löfte om manipuleringssäker lagring (WORM) ska skydda mot.

Förslag:

- Inför `BEFORE UPDATE`-triggers som nekar ändringar av `telemetry_events` och `compliance_reports`. Tillåt radering av `telemetry_events` bara i gallringens transaktion, via samma mekanism med `aiproxy.audit_maintenance` som tombstones använder.
- Låt checkpoints bara tillåta övergången `PENDING` → `ANCHORED`.
- Inför en verifieringskörning, som worker eller CLI, som räknar om varje events hash och signatur och följer kedjan via tombstones och events fram till senaste förankrade huvud.
- Ta med resultatet i den förseglade rapporten, så att rapporten intygar verifierad bevisning och inte bara lagrade siffror.

Kod: [0001_telemetry.sql](../../control-plane/db/migrations/0001_telemetry.sql), [0008_signed_compliance_reports.sql](../../control-plane/db/migrations/0008_signed_compliance_reports.sql), [getDashboardData](../../control-plane/src/lib/dashboard.ts).

*Delvis åtgärdat 2026-09-28 (2A):* migrering `0015_evidence_immutability.sql` gör telemetri, rapporter och checkpoints skrivskyddade och stoppar `TRUNCATE` på alla bevistabeller; gallringen är enda undantaget. Kvar: verifiering av lagrade events i efterhand (2B) — se nedan.

*Åtgärdat 2026-09-28 (2B):* workern sparar den signerade payloaden, och ett timjobb verifierar lagrade events och tombstones mot payload, signatur, kedja och senaste förankrade checkpoint. Resultatet ingår i dashboard och förseglad rapport, och kedjan räknas bara som intakt efter en fullständig körning utan avvikelser de senaste 48 timmarna. Se [specen](../superpowers/specs/2026-09-28-telemetry-reverification-design.md).

**Prioritet P2**

**3. Ingest läser hela bodyn innan storleken kontrolleras.** `POST /api/telemetry/ingest` avvisar en för stor `Content-Length`, men utan den headern, till exempel vid chunked-överföring, läser `request.text()` hela bodyn innan storleken kontrolleras. Ett ogiltigt `Content-Length` hoppar också förbi kontrollen. Det kräver en giltig tenant-nyckel men kan tömma minnet. Använd den befintliga `readBoundedTextBody`, som övriga routes redan använder. Kod: [ingest/route.ts](../../control-plane/src/app/api/telemetry/ingest/route.ts).

**4. Inloggningsspärren använder den första adressen i `X-Forwarded-For`.** De vanligaste proxykonfigurationerna lägger till klientens adress sist i headern i stället för att ersätta den. Då styr klienten själv den första adressen. Det ger två problem:

- En angripare kan kringgå spärren genom att byta adress, eller låsa ute en annan användares adress genom att förfalska den.
- Utan någon av headrarna delar alla anrop hinken `"unknown"`, så fem felaktiga försök låser ute alla.

DPO-nycklarna har 256 bitar, så brute force är inte realistiskt. Den verkliga risken är utlåsning. README kräver att proxyn tar bort headern, men koden kan inte kontrollera det. Inför en konfigurerbar parameter för antal betrodda proxyled och ta adressen närmast den betrodda proxyn. Om ingen betrodd adress finns bör spärren bara gälla nyckeln, inte alla. Kod: [login-throttle.ts](../../control-plane/src/lib/login-throttle.ts).

**5. Tenant-isolering finns bara i applikationen.** Ingen tabell har row-level security. Alla granskade frågor filtrerar korrekt på `organization_id`, men en enda framtida fråga utan filter läcker mellan kunder. Som försvar på djupet: inför RLS med `set_config('aiproxy.organization_id', …, true)` per transaktion och en applikationsroll som inte äger tabellerna. Interna jobb som går över alla organisationer (worker, gallring, checkpoints, metrics) kör då med en separat roll.

**Prioritet P3**

**6. Utloggning ogiltigförklarar inte sessionen.** Sessionen är en signerad cookie som gäller i 8 timmar. Utloggning tar bara bort cookien i webbläsaren, så en kopierad cookie gäller tills den löper ut eller nyckeln återkallas. En sessionsversion per nyckel, som räknas upp vid utloggning och kontrolleras i `validateDPOIdentity`, stänger detta.

**7. Förankringskön kan fastna.** De fem äldsta `PENDING`-checkpointsen försöks igen först varje gång. Om de misslyckas permanent, till exempel för att kvittot aldrig matchar, förankras inga nyare. Gallringen kräver `ANCHORED` och stannar därför också. Markera en checkpoint som permanent misslyckad efter ett antal försök, eller sortera på antal försök.

**8. Dataplanet försöker igen vid alla felsvar, även 400.** En batch som Control Plane avvisar med 400 blockerar hela kön för alltid. Proxyn validerar själv `application_id` och bygger `routing`/`metrics`, så det går inte att utlösa i dag. En framtida skillnad i schemat mellan dataplanet och Control Plane skulle dock stoppa all telemetri. Lägg händelser som får 4xx i karantän i stället för att försöka igen.

**9. Obegränsat nästlingsdjup i ingestschemat.** `jsonValueSchema` är rekursivt utan gräns för djupet. Djupt nästlad JSON inom 1 MiB kan spränga anropsstacken i valideringen och ge 500 för det anropet. Begränsa djupet, till exempel till 16 nivåer.

**Styrkor som bör behållas**

- Hashade nycklar med utgångstid och återkallning.
- Sessionen kontrolleras mot databasen vid varje anrop, så en återkallad nyckel stoppas direkt.
- Kontroll av samma ursprung på alla POST-anrop.
- Jämförelser i konstant tid.
- Advisory-lås med ny kontroll av aktören vid åtkomstadministration.
- Audit i samma transaktion som ändringen.
- Domänseparerade hashar.
- Verifiering av både signatur och fingerprint för telemetri och ankarkvitton.
- Gallring som bara tar bort förankrade events och lämnar tombstones.
