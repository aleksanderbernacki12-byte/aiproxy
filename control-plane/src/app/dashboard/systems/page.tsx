import Link from "next/link";
import { notFound } from "next/navigation";
import { requireDashboardIdentity } from "@/lib/dashboard-auth";
import { listAISystems } from "@/lib/ai-systems";
import { AISystemForm } from "@/components/ai-system-form";
import { riskLabels, statusLabels, type AISystemProfile } from "@/lib/ai-system-profile";

export default async function SystemsPage({ searchParams }: { searchParams: Promise<{ id?: string }> }) {
  const identity = await requireDashboardIdentity();
  const systems = await listAISystems(identity.organizationId);
  const { id } = await searchParams;
  const selected = id ? systems.find((system) => system.id === id) : undefined;
  if (id && !selected) notFound();
  const profile: AISystemProfile = selected ? {
    application_id: selected.applicationId, model: selected.model, name: selected.name,
    provider: selected.provider ?? "", intended_purpose: selected.intendedPurpose,
    risk_class: selected.riskClass, system_owner: selected.systemOwner,
    legal_basis: selected.legalBasis, human_oversight: selected.humanOversight,
    data_categories: selected.dataCategories, deployment_regions: selected.deploymentRegions, status: selected.status,
  } : { application_id: "", model: "", name: "", provider: "", intended_purpose: "", risk_class: "UNCLASSIFIED", system_owner: "", legal_basis: "", human_oversight: "", data_categories: [], deployment_regions: [], status: "ACTIVE" };
  const readOnly = identity.role === "AUDITOR";
  return <div className="space-y-7 p-5 sm:p-8">
    <Link href="/dashboard" className="text-sm text-government underline">Till AI-inventeringen</Link>
    <header><h1 className="font-serif text-3xl">Systemprofiler</h1><p className="mt-2 text-sm text-muted">Dokumentera ansvar, användningsområde och tillsyn. Ange funktioner och referenser, inte personuppgifter eller promptinnehåll.</p></header>
    <section aria-label="Registrerade system" className="rounded-sm border border-line bg-panel p-5">
      {systems.length === 0 ? <p className="text-sm text-muted">Inga systemprofiler har registrerats ännu.</p> : <ul className="divide-y divide-line">{systems.map((system) => <li key={system.id} className="py-3"><Link href={`/dashboard/systems?id=${system.id}`} className="font-semibold text-government underline">{system.name}</Link><p className="break-words text-sm text-muted">{system.applicationId} · {system.model} · {riskLabels[system.riskClass]} · {statusLabels[system.status]}</p></li>)}</ul>}
      {!readOnly && <Link href="/dashboard/systems" className="mt-4 inline-block text-sm font-bold text-government underline">Registrera ny profil</Link>}
    </section>
    {(selected || !readOnly) && <section className="rounded-sm border border-line bg-panel p-5 sm:p-7">
      <h2 className="mb-4 font-serif text-xl">{selected ? selected.name : "Ny systemprofil"}</h2>
      {!readOnly && <p className="mb-4 text-sm text-muted">Applikations-ID och modell identifierar profilen. Samma kombination uppdaterar en befintlig profil. Riskklass och status är dokumentation och ändrar inte automatiskt proxytrafiken.</p>}
      {readOnly && <p className="mb-4 text-sm text-muted">Du har läsbehörighet. En DPO eller administratör kan spara ändringar.</p>}
      <AISystemForm key={selected?.id ?? "new"} profile={profile} readOnly={readOnly} existing={!!selected} />
    </section>}
  </div>;
}
