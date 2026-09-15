import Link from "next/link";
import { ReportButton } from "@/components/report-button";
import { getDashboardData } from "@/lib/dashboard";
import { requireDashboardIdentity } from "@/lib/dashboard-auth";
import { getSecurityAuditEvidence } from "@/lib/security-audit";

export const dynamic = "force-dynamic";

const number = new Intl.NumberFormat("sv-SE");
const date = new Intl.DateTimeFormat("sv-SE", {
  dateStyle: "long",
  timeZone: "Europe/Stockholm",
});
const timestamp = new Intl.DateTimeFormat("sv-SE", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "Europe/Stockholm",
});

export default async function ComplianceReportPage() {
  const identity = await requireDashboardIdentity();
  const [data, administrativeAudit] = await Promise.all([
    getDashboardData(identity.organizationId),
    getSecurityAuditEvidence(identity.organizationId),
  ]);
  if (!data) {
    return (
      <div className="p-8">
        <h1 className="font-serif text-3xl">Rapporten kan inte genereras</h1>
        <p className="mt-3 text-sm text-muted">Den autentiserade organisationen finns inte i databasen.</p>
      </div>
    );
  }

  const generatedAt = new Date();
  const chainIntact = data.summary.chainStatus === "INTACT";
  const reference = `AIP-${data.organization.id.slice(0, 8).toUpperCase()}-${generatedAt.toISOString().slice(0, 10).replaceAll("-", "")}`;

  return (
    <div className="px-4 py-7 sm:px-8 lg:px-12">
      <div className="print-hidden mx-auto mb-5 flex max-w-[900px] items-center justify-between">
        <Link href="/dashboard" className="text-sm font-bold text-government hover:underline">
          ← Tillbaka till inventeringen
        </Link>
        <Link href="/dashboard/reports" className="text-sm font-bold text-government hover:underline">Rapportarkiv</Link>
        <ReportButton mode="print" />
        {identity.role !== "AUDITOR" && (
          <form action="/api/dashboard/reports" method="post">
            <button type="submit" className="min-h-11 rounded-sm border border-government px-4 text-sm font-bold text-government hover:bg-government-light">
              Försegla och ladda ned
            </button>
          </form>
        )}
      </div>

      <article className="report-sheet mx-auto max-w-[900px] border border-line bg-white px-7 py-9 shadow-[0_8px_30px_rgba(20,32,25,0.08)] sm:px-12 sm:py-12">
        <header className="border-b-2 border-government pb-8">
          <div className="flex items-start justify-between gap-8">
            <div>
              <div className="flex items-center gap-3">
                <span className="grid size-10 place-items-center rounded-sm bg-government font-serif text-xl font-bold text-white">A</span>
                <span className="text-xs font-bold uppercase tracking-[0.2em] text-government">Aiproxy Compliance</span>
              </div>
              <p className="mt-10 text-[10px] font-bold uppercase tracking-[0.2em] text-muted">Formellt bevisunderlag</p>
              <h1 className="mt-3 max-w-2xl font-serif text-4xl leading-tight tracking-tight">Rapport över organisationens AI-användning</h1>
            </div>
            <div className="shrink-0 border-l border-line pl-5 text-right text-[10px] uppercase leading-5 tracking-[0.12em] text-muted">
              <p>Referens</p>
              <p className="font-bold text-ink">{reference}</p>
              <p className="mt-3">Upprättad</p>
              <p className="font-bold text-ink">{date.format(generatedAt)}</p>
            </div>
          </div>
        </header>

        <dl className="print-break-inside-avoid grid border-b border-line py-6 sm:grid-cols-2">
          <ReportField label="Organisation" value={data.organization.name} />
          <ReportField label="Organisationens ID" value={data.organization.id} mono />
          <ReportField
            label="Rapportperiod"
            value={
              data.summary.firstEventAt && data.summary.lastEventAt
                ? `${date.format(data.summary.firstEventAt)} – ${date.format(data.summary.lastEventAt)}`
                : "Ingen verifierad period"
            }
          />
          <ReportField label="Datakälla" value="Anonymiserad, ECDSA-signerad telemetri" />
        </dl>

        <ReportSection number="01" title="Översikt över AI-användning">
          <p className="max-w-3xl text-sm leading-6 text-muted">
            Under rapportperioden registrerades {number.format(data.summary.totalEvents)} AI-anrop fördelade på {number.format(data.models.length)} observerade AI-system. Den sammanlagda användningen var {number.format(data.summary.totalTokens)} tokens.
          </p>
          <div className="mt-6 grid grid-cols-3 border-y border-line">
            <ReportMetric label="AI-system" value={number.format(data.models.length)} />
            <ReportMetric label="AI-anrop" value={number.format(data.summary.totalEvents)} />
            <ReportMetric label="Tokens" value={number.format(data.summary.totalTokens)} />
          </div>
          <table className="mt-6 w-full border-collapse text-left text-xs">
            <thead className="border-y border-line bg-[#f4f5f2] text-[9px] uppercase tracking-[0.13em] text-muted">
              <tr>
                <th className="px-3 py-3">Modell</th>
                <th className="px-3 py-3 text-right">Anrop</th>
                <th className="px-3 py-3 text-right">Tokens</th>
                <th className="px-3 py-3 text-right">Policybrott</th>
                <th className="px-3 py-3 text-right">PII</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {data.models.map((model) => (
                <tr key={`${model.applicationId}:${model.model}:${model.observedProvider}`}>
                  <td className="px-3 py-3"><span className="font-mono font-bold">{model.model}</span><br /><span className="text-muted">{model.applicationId}</span></td>
                  <td className="px-3 py-3 text-right tabular-nums">{number.format(model.eventCount)}</td>
                  <td className="px-3 py-3 text-right tabular-nums">{number.format(model.totalTokens)}</td>
                  <td className="px-3 py-3 text-right tabular-nums">{number.format(model.policyViolations)}</td>
                  <td className="px-3 py-3 text-right tabular-nums">{number.format(model.piiIncidents)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </ReportSection>

        <ReportSection number="02" title="Styrning och riskklassificering">
          <p className="text-sm leading-6 text-muted">
            {data.summary.unclassifiedSystems === 0
              ? "Samtliga observerade AI-system har en dokumenterad riskklass och styrningsprofil."
              : `${number.format(data.summary.unclassifiedSystems)} observerade AI-system saknar fastställd riskklass eller styrningsprofil.`}
          </p>
          <div className="mt-5 space-y-3">
            {data.models.map((model) => (
              <div key={`${model.applicationId}:${model.model}:governance`} className="print-break-inside-avoid border border-line p-4 text-xs">
                <div className="flex justify-between gap-4"><strong>{model.governance?.name ?? `${model.applicationId} / ${model.model}`}</strong><strong>{model.governance?.riskClass ?? "UNCLASSIFIED"}</strong></div>
                <p className="mt-2 text-muted">Ändamål: {model.governance?.intendedPurpose ?? "Ej dokumenterat"}</p>
                <p className="mt-1 text-muted">Systemägare: {model.governance?.systemOwner ?? "Ej dokumenterad"}</p>
                <p className="mt-1 text-muted">Rättslig grund: {model.governance?.legalBasis ?? "Ej dokumenterad"}</p>
                <p className="mt-1 text-muted">Mänsklig tillsyn: {model.governance?.humanOversight ?? "Ej dokumenterad"}</p>
              </div>
            ))}
          </div>
        </ReportSection>

        <ReportSection number="03" title="Avvärjda PII-läckor">
          <div className="print-break-inside-avoid flex items-center gap-6 rounded-sm border border-government/20 bg-government-light/50 p-6">
            <p className="font-serif text-5xl text-government">{number.format(data.summary.piiPrevented)}</p>
            <div>
              <p className="text-sm font-bold">Identifierade och lokalt redigerade händelser</p>
              <p className="mt-1 text-xs leading-5 text-muted">
                Värdet omfattar event där både <code>pii_detected</code> och <code>pii_redacted</code> är verifierade som sanna. Klartexten ingår inte i detta underlag.
              </p>
            </div>
          </div>
        </ReportSection>

        <ReportSection number="04" title="Kryptografisk revisionskedja">
          <div className={`print-break-inside-avoid border-l-4 p-5 ${chainIntact ? "border-government bg-government-light/50" : "border-alert bg-alert-light"}`}>
            <div className="flex items-center justify-between gap-5">
              <div>
                <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted">Samlad kedjestatus</p>
                <p className={`mt-2 font-serif text-2xl ${chainIntact ? "text-government" : "text-alert"}`}>
                  {chainIntact ? "Integriteten är intakt" : data.summary.chainStatus === "NO_EVIDENCE" ? "Underlag saknas" : "Avvikelse kräver granskning"}
                </p>
              </div>
              <span className={`grid size-11 place-items-center rounded-full border-2 text-xl font-bold ${chainIntact ? "border-government text-government" : "border-alert text-alert"}`}>
                {chainIntact ? "✓" : "!"}
              </span>
            </div>
          </div>
          <dl className="mt-6 grid grid-cols-3 divide-x divide-line border-y border-line py-4 text-center">
            <ChainCount label="Verifierade event" value={data.summary.verifiedEvents} />
            <ChainCount label="Kedjebrott" value={data.summary.compromisedEvents} />
            <ChainCount label="Ogiltiga signaturer" value={data.summary.invalidSignatures} />
          </dl>
          <p className="mt-5 text-xs leading-5 text-muted">
            Varje event är signerat med ECDSA P-256 och länkat till föregående eventhash. Kontrollplanet verifierar signaturen, eventhashen och föregående länks hash innan eventet registreras i revisionskedjan.
          </p>
          {data.checkpoint && (
            <dl className="mt-5 border border-line p-4 text-xs">
              <dt className="font-bold uppercase tracking-[0.12em] text-muted">Senaste Merkle-checkpoint</dt>
              <dd className="mt-2 break-all font-mono">{data.checkpoint.rootHash}</dd>
              <dd className="mt-2 text-muted">
                {number.format(data.checkpoint.leafCount)} kedjehuvuden · {timestamp.format(data.checkpoint.createdAt)}
              </dd>
              <dt className="mt-4 font-bold uppercase tracking-[0.12em] text-muted">Extern förankring</dt>
              <dd className="mt-2">
                {data.checkpoint.anchorStatus === "ANCHORED" && data.checkpoint.anchoredAt
                  ? `Verifierat ankarkvitto ${data.checkpoint.anchorId ?? ""} · ${timestamp.format(data.checkpoint.anchoredAt)}`
                  : "Inväntar verifierat ankarkvitto"}
              </dd>
            </dl>
          )}
        </ReportSection>

        <ReportSection number="05" title="Administrativ säkerhetslogg">
          <div className={`print-break-inside-avoid border-l-4 p-5 ${administrativeAudit.status === "INTACT" ? "border-government bg-government-light/50" : administrativeAudit.status === "NO_EVIDENCE" ? "border-line bg-[#f4f5f2]" : "border-alert bg-alert-light"}`}>
            <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-muted">Append-only-kedja</p>
            <p className={`mt-2 font-serif text-2xl ${administrativeAudit.status === "ATTENTION_REQUIRED" ? "text-alert" : "text-government"}`}>
              {administrativeAudit.status === "INTACT" ? "Verifierad och sammanhängande" : administrativeAudit.status === "NO_EVIDENCE" ? "Inga administrativa event" : "Integritetsfel kräver utredning"}
            </p>
          </div>
          <dl className="mt-5 border border-line p-4 text-xs">
            <dt className="font-bold uppercase tracking-[0.12em] text-muted">Registrerade event</dt>
            <dd className="mt-2">{number.format(administrativeAudit.eventCount)} · senaste sekvens {administrativeAudit.latestSequence}</dd>
            <dt className="mt-4 font-bold uppercase tracking-[0.12em] text-muted">Senaste eventhash</dt>
            <dd className="mt-2 break-all font-mono">{administrativeAudit.latestEventHash || "Ingen hash ännu"}</dd>
            {administrativeAudit.latestEventAt && <dd className="mt-2 text-muted">Senast uppdaterad {timestamp.format(administrativeAudit.latestEventAt)}</dd>}
            <dt className="mt-4 font-bold uppercase tracking-[0.12em] text-muted">Extern förankring</dt>
            <dd className="mt-2">
              {administrativeAudit.anchor?.status === "ANCHORED" && administrativeAudit.anchor.anchoredAt
                ? `Verifierat ankarkvitto ${administrativeAudit.anchor.anchorId ?? ""} · ${timestamp.format(administrativeAudit.anchor.anchoredAt)}`
                : administrativeAudit.anchor ? "Inväntar verifierat ankarkvitto" : "Ingen audit-checkpoint ännu"}
            </dd>
            {administrativeAudit.anchor && <dd className="mt-2 break-all font-mono">{administrativeAudit.anchor.rootHash}</dd>}
          </dl>
          <p className="mt-5 text-xs leading-5 text-muted">Rapportens signerade snapshot innehåller kedjans verifieringsstatus, eventantal och senaste hash före rapportens egen förseglingshändelse.</p>
        </ReportSection>

        <footer className="mt-12 border-t border-line pt-5 text-[9px] leading-4 text-muted">
          <div className="flex justify-between gap-8">
            <p className="max-w-xl">Detta dokument sammanfattar tekniskt bevismaterial för organisationens AI-styrning. Underlaget bygger endast på behandlad telemetri och innehåller inga LLM-promptar eller personuppgifter i klartext.</p>
            <p className="shrink-0 text-right">Genererad {timestamp.format(generatedAt)}<br />{reference}</p>
          </div>
        </footer>
      </article>
    </div>
  );
}

function ReportField({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="border-line py-3 sm:border-r sm:px-5 sm:odd:pl-0 sm:even:border-r-0">
      <dt className="text-[9px] font-bold uppercase tracking-[0.14em] text-muted">{label}</dt>
      <dd className={`mt-1.5 text-xs font-bold ${mono ? "font-mono" : ""}`}>{value}</dd>
    </div>
  );
}

function ReportSection({ number: sectionNumber, title, children }: { number: string; title: string; children: React.ReactNode }) {
  return (
    <section className="mt-10">
      <div className="mb-5 flex items-baseline gap-4 border-b border-line pb-3">
        <span className="text-[10px] font-bold tracking-[0.15em] text-government">{sectionNumber}</span>
        <h2 className="font-serif text-2xl">{title}</h2>
      </div>
      {children}
    </section>
  );
}

function ReportMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="border-r border-line px-4 py-4 last:border-r-0">
      <p className="text-[9px] font-bold uppercase tracking-[0.12em] text-muted">{label}</p>
      <p className="mt-2 text-xl font-bold tabular-nums">{value}</p>
    </div>
  );
}

function ChainCount({ label, value }: { label: string; value: number }) {
  return (
    <div className="px-2">
      <dt className="text-[9px] font-bold uppercase tracking-[0.1em] text-muted">{label}</dt>
      <dd className="mt-2 text-lg font-bold tabular-nums">{number.format(value)}</dd>
    </div>
  );
}
