import Link from "next/link";
import { notFound } from "next/navigation";
import { parseAuditCursor } from "@/lib/audit-pagination";
import { requireDashboardOrganizationId } from "@/lib/dashboard-auth";
import { getSecurityAuditLedger } from "@/lib/security-audit";

export const dynamic = "force-dynamic";

const timestamp = new Intl.DateTimeFormat("sv-SE", {
  dateStyle: "medium", timeStyle: "short", timeZone: "Europe/Stockholm",
});

function field(data: Record<string, unknown>, name: string) {
  return typeof data[name] === "string" ? data[name] : "—";
}

export default async function SecurityAuditPage({ searchParams }: { searchParams: Promise<{ before?: string | string[] }> }) {
  const organizationId = await requireDashboardOrganizationId();
  let before: bigint | undefined;
  try { before = parseAuditCursor((await searchParams).before); } catch { notFound(); }
  const ledger = await getSecurityAuditLedger(organizationId, before);
  return (
    <div className="px-5 py-7 sm:px-8 lg:px-10 lg:py-9">
      <header className="border-b border-line pb-7">
        <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-government">Administrativ revision</p>
        <h1 className="mt-3 font-serif text-3xl tracking-tight sm:text-4xl">Säkerhetslogg</h1>
        <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">Append-only register över credential-, nyckel-, styrnings- och rapportåtgärder.</p>
      </header>
      <div className={`mt-7 border-l-4 p-5 ${ledger.valid ? "border-government bg-government-light" : "border-alert bg-alert-light"}`}>
        <p className="text-xs font-bold uppercase tracking-[0.14em] text-muted">Kedjestatus</p>
        <p className={`mt-2 font-serif text-2xl ${ledger.valid ? "text-government" : "text-alert"}`}>{ledger.evidence.status === "NO_EVIDENCE" ? "Inga revisionsbevis ännu" : ledger.valid ? "Verifierad och sammanhängande" : "Integritetsfel kräver utredning"}</p>
        <p className="mt-2 text-xs text-muted">
          {ledger.evidence.anchor?.status === "ANCHORED"
            ? `Externt förankrad · ${ledger.evidence.anchor.anchorId ?? "verifierat kvitto"}`
            : ledger.evidence.anchor ? "Extern förankring väntar" : "Ingen extern checkpoint ännu"}
        </p>
      </div>
      <section className="mt-6 overflow-hidden border border-line bg-panel">
        {ledger.events.length === 0 ? <p className="p-10 text-center text-sm text-muted">Inga administrativa händelser på denna sida.</p> : (
          <div className="overflow-x-auto"><table className="w-full min-w-[880px] text-left text-xs">
            <thead className="bg-[#f0f1ed] text-[10px] uppercase tracking-[0.14em] text-muted"><tr><th className="px-5 py-4">Sekvens</th><th className="px-5 py-4">Tid</th><th className="px-5 py-4">Åtgärd</th><th className="px-5 py-4">Aktör</th><th className="px-5 py-4">Resurs</th><th className="px-5 py-4">Hash</th></tr></thead>
            <tbody className="divide-y divide-line">{ledger.events.map((event) => <tr key={event.eventId}>
              <td className="px-5 py-4 font-mono">{event.sequence.toString()}</td><td className="px-5 py-4">{timestamp.format(event.occurredAt)}</td>
              <td className="px-5 py-4 font-bold">{field(event.eventData, "action")}</td><td className="px-5 py-4">{field(event.eventData, "actor_type")} · {field(event.eventData, "actor_id")}</td>
              <td className="px-5 py-4">{field(event.eventData, "resource_type")}<br /><span className="font-mono text-[10px] text-muted">{field(event.eventData, "resource_id")}</span></td>
              <td className="px-5 py-4 font-mono">{event.eventHash.slice(0, 16)}…</td>
            </tr>)}</tbody>
          </table></div>
        )}
      </section>
      <nav aria-label="Sidor i säkerhetsloggen" className="mt-4 flex flex-wrap gap-5 text-sm text-government">
        {before !== undefined && <Link href="/dashboard/audit" className="underline">Senaste händelserna</Link>}
        {ledger.nextCursor && <Link href={`/dashboard/audit?before=${ledger.nextCursor}`} className="underline">Äldre händelser</Link>}
      </nav>
      <p className="mt-3 text-xs text-muted">Upp till 200 händelser per sida. Kedjestatus avser hela organisationens logg.</p>
    </div>
  );
}
