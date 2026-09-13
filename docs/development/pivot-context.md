# Kontext inför kommande byggsteg

Baslinjen är den befintliga implementationen vid `8a7da8d6fb683ec3e92fb2b50aed44d9054a8e1d`, kompletterad med regressionstester i den commit som inför detta dokument. Produktionslogiken ändras inte i denna checkpoint. Produktens nya inriktning och nästa implementation specificeras i kommande bygg-prompter; de ska inte gissas utifrån denna text.

**Kontext-prompt att ge till nästa kod-LLM**

> Du arbetar vidare i Aiproxy. Nuvarande routing och rate-limiting är en etablerad baslinje med regressionstester och en separat checkpoint-commit. Behandla dem som befintliga komponenter att integrera med.
>
> Använd denna prompt som övergripande ram. Implementera endast det konkreta byggsteg användaren därefter ger dig, ett steg i taget. En beskrivning av en framtida pivot är inte en instruktion att börja bygga den eller skriva om kärnan.
>
> Läs aktuella repo-instruktioner, arbetskatalogens Git-status och relevanta tester före ändringar. Bevara användarens pågående arbete. Behåll befintliga routingregler, vidarebefordran, kvoter, klientisolering mellan limiterinstanser, felkoder och publika konfigurationsfält där byggsteget inte uttryckligen ändrar deras beteende.
>
> Utöka genom avgränsade komponenter och befintliga gränssnitt. Gör ingen generell omskrivning av proxy, routing, rate-limiting eller konfiguration som en sidoeffekt av ett annat byggsteg. Om en uttryckligen begärd funktion kräver ändring i kärnan, beskriv konkret vilka befintliga beteenden som påverkas och gör minsta nödvändiga ändring med relevanta regressionstester.
>
> Använd testerna som kontrakt för fungerande beteende. Försvaga, radera eller hoppa inte över dem för att få en ny implementation att bli grön. En avsiktlig beteendeförändring ska dokumenteras med före/efter och testas. Baslinjen gör inte kända säkerhetsbrister till krav som måste bevaras: sådana ska hanteras som uttryckliga, avgränsade rättningar.
>
> Kör relevanta tester under utvecklingen samt gofmt, go vet ./... och go test ./... -race -count=1 före leverans. Dokumentera eventuella kontroller som inte kunde köras. Spara varje färdigt byggsteg i en separat, tydligt avgränsad commit när användarens instruktioner medger det. Rapportera ändrat beteende, testresultat och commit. Påbörja nästa byggsteg först när dess prompt har kommit.

**Skyddat beteende och testunderlag**

| Område | Befintligt beteende som testerna skyddar |
|---|---|
| Routeval | Matchande modellroute prioriteras över path-route. Modellroutes använder första match i konfigurerad ordning. Saknad, omatchad eller feltypad modell faller tillbaka till path/default. |
| Vidarebefordran | Path-route tar bort sitt prefix; modellroute behåller sökvägen. Metod, body, query med upprepade parametrar och upstream-autentiseringsheader bevaras. |
| Viktad routing och failover | Befintliga tester täcker viktgränser, kandidatval, fallback, bodyåteranvändning och att HTTP-felsvar inte automatiskt triggar failover. |
| Requestkvoter | Ett accepterat anrop förbrukar en slot i ett rullande fönster. Samtidiga anrop kan inte överskrida samma limiterinstans kvot. Avvisade försök flyttar inte fram fönstrets slut. |
| Kvotval | En explicit klientkvot prioriteras framför routens kvot. Samma klient delar sin kvot över path- och modellroutes; olika klienters limiterinstanser är oberoende. |
| Tokenkvoter | Rapporterad usage räknas efter svaret. Samtidiga Add tappar inte tokens. Exakt utgångsgräns tar bara bort gammal usage. Detta är efterhandsräkning, inte reservation eller ett absolut tak för pågående anrop. |
| Klientsvar | Rate-limit-avslag ger 429 och relevanta limitheaders; requestkvotens avslag ger positiv Retry-After. Avslag ska inte nå upstream och tokenavslag räknas separat från requestavslag. |
| Övrig befintlig täckning | Per-route- och per-IP-kvoter, modellprioritet, globmatchning, konfigurationsvalidering och reloadtester finns sedan tidigare. |

De nya kombinationstesterna ligger i [routing_limits_contract_test.go](../../internal/proxy/routing_limits_contract_test.go). De nya deterministiska fönster- och bokföringstesterna ligger i [rolling_contract_test.go](../../internal/limiter/rolling_contract_test.go). Befintliga tester finns också i `internal/proxy/proxy_test.go`, `internal/proxy/weightedrouting_test.go`, `internal/limiter/`, `internal/iplimiter/`, `internal/cli/` och `internal/config/`.

Ett snabbt urval av checkpointens nya tester:

```sh
go test ./internal/limiter ./internal/proxy -race -count=1 \
  -run 'TestRoutingContract_|TestLimiter_RollingWindow|TestTokenLimiter_(RollingWindow|ConcurrentAccounting)'
```

Full verifiering:

```sh
gofmt -l .
go vet ./...
go test ./... -race -count=1
```

`gofmt -l .` ska inte skriva ut några filer. CI har redan motsvarande kontroller på Linux, macOS och Windows. Lokala tester på en plattform ersätter inte resultat från de andra plattformarna.

Verifierat för denna checkpoint den 13 september 2026 på macOS/ARM64 med Go 1.27.1: alla sex nya testfunktioner inklusive åtta routingfall passerade, hela testsviten passerade med race-detektorn, `go vet ./...` passerade och gofmt rapporterade inga oformaterade filer. Hela testkörningen mätte 93,6 % statement-täckning i `internal/proxy`, 94,3 % i `internal/limiter` och 100 % i `internal/iplimiter`; siffrorna omfattar också de befintliga testerna och innebär inte att alla beteenden är täckta.

Checkpointen är ett regressionsskydd, inte en säkerhetscertifiering. Tidigare identifierade frågor om delad svarscache, policy vid replay och retries efter osäkert upstream-utfall är separata rättningsuppgifter. De nya testerna kräver inte att dessa brister bevaras.
