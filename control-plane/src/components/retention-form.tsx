"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { RetentionCommand } from "@/lib/retention-command";

export function RetentionForm({ days, held }: { days: number | null; held: boolean }) {
  const router = useRouter();
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const inputClass = "mt-2 block w-full rounded-sm border border-line bg-white px-3 py-2";
  async function save(body: RetentionCommand) {
    setSaving(true); setMessage("");
    try {
      const response = await fetch("/api/dashboard/retention", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      if (response.redirected) { setMessage("Sessionen har gått ut. Logga in igen."); return; }
      const result = await response.json();
      if (!response.ok) { setMessage(result.error ?? "Ändringen kunde inte sparas."); return; }
      setMessage("Ändringen har sparats och revisionsloggats.");
      router.refresh();
    } catch { setMessage("Anslutningen misslyckades. Försök igen."); }
    finally { setSaving(false); }
  }
  return <div className="space-y-6">
    <form onSubmit={(event) => {
      event.preventDefault();
      void save({ command: "set", days: Number(new FormData(event.currentTarget).get("days")) });
    }}>
      <fieldset disabled={saving} className="space-y-4">
        <label className="block text-sm font-semibold">Lagringstid i dagar (30–3650)
          <input key={days} name="days" type="number" min={30} max={3650} step={1} required defaultValue={days ?? 365} className={inputClass} />
        </label>
        <p className="text-sm text-muted">En kortare lagringstid kan leda till gallring vid nästa schemalagda körning. Ett aktivt bevarandestopp fortsätter att gälla.</p>
        <button className="rounded-sm bg-government px-4 py-2 text-sm font-bold text-white">Spara lagringstid</button>
      </fieldset>
    </form>
    {days !== null && <form key={String(held)} onSubmit={(event) => {
      event.preventDefault();
      void save({ command: held ? "release" : "hold", reason: String(new FormData(event.currentTarget).get("reason")) });
    }}>
      <fieldset disabled={saving} className="space-y-4 border-t border-line pt-5">
        <h2 className="font-serif text-xl">{held ? "Häv bevarandestopp" : "Aktivera bevarandestopp"}</h2>
        <p className="text-sm text-muted">{held ? "När stoppet hävs kan schemalagd gallring återupptas enligt lagringstiden." : "Stoppar kommande gallring av organisationens telemetri. Redan gallrade data återställs inte."}</p>
        <label className="block text-sm font-semibold">Ärendereferens eller skäl (utan personuppgifter)
          <input name="reason" required maxLength={500} className={inputClass} />
        </label>
        <button className="rounded-sm border border-government px-4 py-2 text-sm font-bold text-government">{held ? "Häv bevarandestopp" : "Aktivera bevarandestopp"}</button>
      </fieldset>
    </form>}
    <p role="status" aria-live="polite" className="text-sm">{saving ? "Sparar…" : message}</p>
  </div>;
}
