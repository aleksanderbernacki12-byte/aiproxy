"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { riskClasses, systemStatuses, riskLabels, statusLabels, type AISystemProfile } from "@/lib/ai-system-profile";

export function AISystemForm({ profile, readOnly, existing }: { profile: AISystemProfile; readOnly: boolean; existing: boolean }) {
  const router = useRouter();
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const inputClass = "mt-1 w-full rounded-sm border border-line bg-white px-3 py-2 text-sm disabled:bg-paper";
  const fields = [
    ["application_id", "Applikations-ID", 160], ["model", "Modell", 160],
    ["name", "Systemnamn", 200], ["provider", "Leverantör (valfritt)", 160],
    ["system_owner", "Systemansvarig funktion", 200],
    ["intended_purpose", "Avsett användningsområde", 4000],
    ["legal_basis", "Rättslig grund", 4000], ["human_oversight", "Mänsklig tillsyn", 4000],
  ] as const;
  return <form onSubmit={async (event) => {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const value = Object.fromEntries(data.entries());
    const body = { ...value,
      data_categories: String(value.data_categories ?? "").split("\n").map((s) => s.trim()).filter(Boolean),
      deployment_regions: String(value.deployment_regions ?? "").split("\n").map((s) => s.trim()).filter(Boolean),
    };
    setSaving(true); setMessage("");
    try {
      const response = await fetch("/api/dashboard/systems", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      if (response.redirected) { setMessage("Sessionen har gått ut. Logga in igen innan du sparar."); return; }
      const result = await response.json();
      if (!response.ok) { setMessage(result.error ?? "Profilen kunde inte sparas."); return; }
      setMessage("Profilen har sparats och ändringen har revisionsloggats.");
      router.replace(`/dashboard/systems?id=${encodeURIComponent(result.id)}`);
      router.refresh();
    } catch { setMessage("Anslutningen misslyckades. Dina uppgifter finns kvar i formuläret."); }
    finally { setSaving(false); }
  }} className="space-y-5">
    <fieldset disabled={readOnly || saving} className="grid gap-5 sm:grid-cols-2">
      {fields.map(([field, label, max]) => <label key={field} className={`block text-sm font-semibold ${max === 4000 ? "sm:col-span-2" : ""}`}>
        {label}
        {max === 4000
          ? <textarea name={field} defaultValue={profile[field]} maxLength={max} required rows={3} className={inputClass} />
          : <input name={field} defaultValue={profile[field]} maxLength={max} required={field !== "provider"} readOnly={existing && (field === "application_id" || field === "model")} className={inputClass} />}
      </label>)}
      <label className="text-sm font-semibold">Riskklass<select name="risk_class" defaultValue={profile.risk_class} className={inputClass}>{riskClasses.map((risk) => <option key={risk} value={risk}>{riskLabels[risk]}</option>)}</select></label>
      <label className="text-sm font-semibold">Status<select name="status" defaultValue={profile.status} className={inputClass}>{systemStatuses.map((status) => <option key={status} value={status}>{statusLabels[status]}</option>)}</select></label>
      <label className="text-sm font-semibold">Datakategorier (en per rad)<textarea name="data_categories" defaultValue={profile.data_categories.join("\n")} rows={3} maxLength={4830} className={inputClass} /></label>
      <label className="text-sm font-semibold">Driftregioner (en per rad)<textarea name="deployment_regions" defaultValue={profile.deployment_regions.join("\n")} rows={3} maxLength={4830} className={inputClass} /></label>
    </fieldset>
    <p role="status" aria-live="polite" className="text-sm">{message}</p>
    {!readOnly && <button disabled={saving} className="rounded-sm bg-government px-5 py-2.5 text-sm font-bold text-white disabled:opacity-50">{saving ? "Sparar…" : "Spara profil"}</button>}
  </form>;
}
