import { ReportButton } from "@/components/report-button";
import { getDashboardData } from "@/lib/dashboard";
import { requireDashboardOrganizationId } from "@/lib/dashboard-auth";

export const dynamic = "force-dynamic";

const number = new Intl.NumberFormat("sv-SE");
const date = new Intl.DateTimeFormat("sv-SE", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "Europe/Stockholm",
});

export default async function DashboardPage() {
  const organizationId = await requireDashboardOrganizationId();
  const data = await getDashboardData(organizationId);
  if (!data) return <ConfigurationRequired organizationMissing />;

  const maxTokens = Math.max(...data.models.map((model) => model.totalTokens), 1);
  const chainIntact = data.summary.chainStatus === "INTACT";

  return (
    <div className="px-5 py-7 sm:px-8 lg:px-10 lg:py-9">
      <div className="flex flex-col justify-between gap-5 border-b border-line pb-7 sm:flex-row sm:items-end">
        <div>
          <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-government">
            AI-inventering · {data.organization.name}
          </p>
          <h1 className="mt-3 font-serif text-3xl tracking-tight sm:text-4xl">Organisationens AI-användning</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">
            Sammanställning av behandlad telemetri från organisationens anslutna data plane-instanser.
          </p>
        </div>
        <ReportButton />
      </div>

      <section aria-label="Sammanfattning" className="grid border-b border-line md:grid-cols-4">
        <Metric label="Aktiva AI-modeller" value={number.format(data.models.length)} detail={`${number.format(data.summary.totalEvents)} registrerade anrop`} />
        <Metric label="Bearbetade tokens" value={number.format(data.summary.totalTokens)} detail="In- och utgående tokens" />
        <Metric
          label="Revisionskedja"
          value={chainIntact ? "Intakt" : data.summary.chainStatus === "NO_EVIDENCE" ? "Inväntar data" : "Kräver åtgärd"}
          detail={`${number.format(data.summary.verifiedEvents)} kryptografiskt verifierade event`}
          status={data.summary.chainStatus}
        />
        <Metric
          label="Styrningsluckor"
          value={number.format(data.summary.unclassifiedSystems)}
          detail="Observerade system utan fastställd riskklass"
          status={data.summary.unclassifiedSystems > 0 ? "ATTENTION_REQUIRED" : "INTACT"}
        />
      </section>

      <section className="mt-8 overflow-hidden rounded-sm border border-line bg-panel shadow-[0_1px_2px_rgba(20,32,25,0.04)]">
        <div className="flex flex-col justify-between gap-3 border-b border-line px-5 py-5 sm:flex-row sm:items-center sm:px-6">
          <div>
            <h2 className="font-serif text-xl">Modellregister</h2>
            <p className="mt-1 text-xs text-muted">Observerade applikations- och modellkombinationer med styrningsstatus</p>
          </div>
          {data.summary.lastEventAt && (
            <p className="text-xs text-muted">Senast uppdaterad {date.format(data.summary.lastEventAt)}</p>
          )}
        </div>
        {data.models.length === 0 ? (
          <div className="px-6 py-16 text-center">
            <p className="font-serif text-xl">Ingen behandlad telemetri ännu</p>
            <p className="mt-2 text-sm text-muted">Modeller visas när signerade event har verifierats av workern.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] border-collapse text-left">
              <thead className="bg-[#f0f1ed] text-[10px] uppercase tracking-[0.14em] text-muted">
                <tr>
                  <th className="px-6 py-3.5 font-bold">AI-modell</th>
                  <th className="px-5 py-3.5 font-bold">Anrop</th>
                  <th className="px-5 py-3.5 font-bold">Tokens</th>
                  <th className="px-5 py-3.5 font-bold">Riskklass</th>
                  <th className="px-5 py-3.5 text-right font-bold">Policybrott</th>
                  <th className="px-6 py-3.5 text-right font-bold">PII-incidenter</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {data.models.map((model) => (
                  <tr key={`${model.applicationId}:${model.model}:${model.observedProvider}`} className="hover:bg-white">
                    <td className="px-6 py-5">
                      <div className="font-mono text-sm font-bold">{model.model}</div>
                      <div className="mt-1 text-xs text-muted">{model.applicationId} · {model.observedProvider}</div>
                      <div className="mt-1 text-xs text-muted">Senast använd {date.format(model.lastSeenAt)}</div>
                    </td>
                    <td className="px-5 py-5 text-sm tabular-nums">{number.format(model.eventCount)}</td>
                    <td className="w-[32%] px-5 py-5">
                      <div className="flex items-center gap-4">
                        <span className="w-24 text-sm font-bold tabular-nums">{number.format(model.totalTokens)}</span>
                        <span className="h-1.5 flex-1 overflow-hidden bg-government-light">
                          <span className="block h-full bg-government" style={{ width: `${Math.max((model.totalTokens / maxTokens) * 100, 2)}%` }} />
                        </span>
                      </div>
                    </td>
                    <td className="px-5 py-5 text-xs font-bold">
                      <span className={model.governance?.riskClass === "HIGH" || model.governance?.riskClass === "PROHIBITED" ? "text-alert" : model.governance && model.governance.riskClass !== "UNCLASSIFIED" ? "text-government" : "text-[#76652e]"}>
                        {model.governance?.riskClass ?? "UNCLASSIFIED"}
                      </span>
                    </td>
                    <td className="px-5 py-5 text-right text-sm font-bold tabular-nums">
                      <IncidentCount value={model.policyViolations} />
                    </td>
                    <td className="px-6 py-5 text-right text-sm font-bold tabular-nums">
                      <IncidentCount value={model.piiIncidents} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <div className="mt-8 grid gap-4 lg:grid-cols-3">
        <EvidenceCard
          title="AI-styrningsregister"
          value={data.summary.unclassifiedSystems === 0 ? "Komplett klassificerat" : `${number.format(data.summary.unclassifiedSystems)} luckor`}
          description="Riskklass, ändamål, ansvarig och mänsklig tillsyn kopplas till varje observerat AI-system."
          warning={data.summary.unclassifiedSystems > 0}
        />
        <EvidenceCard
          title="PII-skydd"
          value={`${number.format(data.summary.piiPrevented)} avvärjda läckor`}
          description="Personuppgifter identifierades och redigerades lokalt innan anropet nådde LLM-leverantören."
        />
        <EvidenceCard
          title="Kedjeintegritet"
          value={chainIntact ? "Verifierad och sammanhängande" : "Avvikelse registrerad"}
          description={data.checkpoint
            ? `${number.format(data.summary.compromisedEvents)} kedjebrott · Merkle ${data.checkpoint.anchorStatus === "ANCHORED" ? "externt förankrad" : "väntar på extern förankring"}`
            : `${number.format(data.summary.compromisedEvents)} kedjebrott · Merkle-checkpoint inväntas`}
          warning={!chainIntact && data.summary.chainStatus !== "NO_EVIDENCE"}
        />
      </div>
    </div>
  );
}

function Metric({ label, value, detail, status }: { label: string; value: string; detail: string; status?: string }) {
  return (
    <article className="border-line py-6 md:border-r md:px-7 md:first:pl-0 md:last:border-r-0">
      <div className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-[0.14em] text-muted">
        {status && <span className={`size-2 rounded-full ${status === "INTACT" ? "bg-[#277553]" : status === "NO_EVIDENCE" ? "bg-[#9a8a59]" : "bg-alert"}`} />}
        {label}
      </div>
      <p className="mt-3 text-2xl font-bold tracking-tight">{value}</p>
      <p className="mt-1 text-xs text-muted">{detail}</p>
    </article>
  );
}

function IncidentCount({ value }: { value: number }) {
  return value > 0 ? (
    <span className="inline-flex min-w-8 justify-center rounded-sm bg-alert-light px-2 py-1 text-alert">{number.format(value)}</span>
  ) : (
    <span className="text-muted">0</span>
  );
}

function EvidenceCard({ title, value, description, warning = false }: { title: string; value: string; description: string; warning?: boolean }) {
  return (
    <article className="rounded-sm border border-line bg-panel p-6">
      <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-muted">{title}</p>
      <p className={`mt-4 font-serif text-xl ${warning ? "text-alert" : "text-government"}`}>{value}</p>
      <p className="mt-2 text-sm leading-6 text-muted">{description}</p>
    </article>
  );
}

function ConfigurationRequired({ organizationMissing = false }: { organizationMissing?: boolean }) {
  return (
    <div className="px-5 py-10 sm:px-8 lg:px-10">
      <div className="max-w-2xl rounded-sm border border-[#d5caa8] bg-[#faf6e9] p-7">
        <p className="text-[10px] font-bold uppercase tracking-[0.16em] text-[#76652e]">Säker tenantgräns</p>
        <h1 className="mt-3 font-serif text-3xl">Dashboarden saknar organisationskontext</h1>
        <p className="mt-3 text-sm leading-6 text-muted">
          {organizationMissing
            ? "Den konfigurerade organisationen finns inte i databasen."
            : "Dashboardens organisationskontext är inte korrekt konfigurerad."}
        </p>
      </div>
    </div>
  );
}
