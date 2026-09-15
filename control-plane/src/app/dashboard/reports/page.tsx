import Link from "next/link";
import { listSealedReports } from "@/lib/compliance-report";
import { requireDashboardOrganizationId } from "@/lib/dashboard-auth";

export const dynamic = "force-dynamic";

const timestamp = new Intl.DateTimeFormat("sv-SE", {
  dateStyle: "medium",
  timeStyle: "short",
  timeZone: "Europe/Stockholm",
});

export default async function ReportArchivePage() {
  const organizationId = await requireDashboardOrganizationId();
  const reports = await listSealedReports(organizationId);
  return (
    <div className="px-5 py-7 sm:px-8 lg:px-10 lg:py-9">
      <header className="flex flex-col justify-between gap-5 border-b border-line pb-7 sm:flex-row sm:items-end">
        <div>
          <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-government">Bevisarkiv</p>
          <h1 className="mt-3 font-serif text-3xl tracking-tight sm:text-4xl">Förseglade compliance-rapporter</h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-muted">Oföränderliga, Ed25519-signerade snapshots som kan verifieras offline.</p>
        </div>
        <Link href="/dashboard/report" className="inline-flex min-h-11 items-center rounded-sm bg-government px-5 text-sm font-bold text-white">Öppna aktuell rapport</Link>
      </header>

      <section className="mt-8 overflow-hidden rounded-sm border border-line bg-panel">
        {reports.length === 0 ? (
          <div className="px-6 py-16 text-center">
            <p className="font-serif text-xl">Inga förseglade rapporter</p>
            <p className="mt-2 text-sm text-muted">Försegla den aktuella rapporten för att skapa den första arkivposten.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] border-collapse text-left text-xs">
              <thead className="bg-[#f0f1ed] text-[10px] uppercase tracking-[0.14em] text-muted">
                <tr><th className="px-6 py-4">Utfärdad</th><th className="px-5 py-4">Utfärdare</th><th className="px-5 py-4">Payload-hash</th><th className="px-5 py-4">Signeringsnyckel</th><th className="px-6 py-4 text-right">Artefakt</th></tr>
              </thead>
              <tbody className="divide-y divide-line">
                {reports.map((report) => (
                  <tr key={report.id}>
                    <td className="px-6 py-5 font-bold">{timestamp.format(report.createdAt)}<br /><span className="font-mono text-[10px] font-normal text-muted">{report.id}</span></td>
                    <td className="px-5 py-5">{report.generatedByLabel}<br /><span className="text-muted">{report.generatedByRole}</span></td>
                    <td className="px-5 py-5 font-mono">{report.payloadHash.slice(0, 16)}…</td>
                    <td className="px-5 py-5 font-mono">{report.signingKeyId.slice(0, 16)}…<br /><a href={`/api/dashboard/report-keys/${report.signingKeyId}`} className="font-sans font-bold text-government hover:underline">Hämta publiknyckel</a></td>
                    <td className="px-6 py-5 text-right"><a href={`/api/dashboard/reports/${report.id}`} className="font-bold text-government hover:underline">Ladda ned JSON</a></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {reports.length === 100 && <p className="mt-3 text-right text-xs text-muted">De 100 senast utfärdade rapporterna visas.</p>}
    </div>
  );
}
