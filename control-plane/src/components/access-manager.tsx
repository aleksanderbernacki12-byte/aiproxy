"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import type { AccessCommand } from "@/lib/access-command";

type Credential = { id: string; label: string; role: string; status: string; expiresAt: string; current: boolean; revoked: boolean };
export function AccessManager({ credentials }: { credentials: Credential[] }) {
  const router = useRouter();
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [newKey, setNewKey] = useState("");
  const [confirmId, setConfirmId] = useState<string | null>(null);
  async function submit(input: AccessCommand) {
    setSaving(true); setMessage("");
    try {
      const response = await fetch("/api/dashboard/access", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(input) });
      if (response.redirected) { setMessage("Sessionen har gått ut. Logga in igen."); return; }
      const result = await response.json();
      if (!response.ok) { setMessage(result.error ?? "Ändringen kunde inte sparas."); return; }
      if (result.access_key) setNewKey(result.access_key);
      setConfirmId(null);
      setMessage(input.command === "create" ? "Nyckeln har skapats och revisionsloggats." : "Åtkomsten har återkallats och revisionsloggats.");
      router.refresh();
    } catch { setMessage("Anslutningen misslyckades. Kontrollera listan före ett nytt försök. Om en nyckel skapades utan att visas, återkalla den och skapa en ny."); }
    finally { setSaving(false); }
  }
  const inputClass = "mt-2 block w-full rounded-sm border border-line bg-white px-3 py-2";
  return <div className="space-y-6">
    {newKey && <section aria-label="Ny åtkomstnyckel" className="space-y-3 border border-government bg-government-light p-5">
      <p className="text-sm">Spara nyckeln i en säker lösenordshanterare. Den visas bara här och kan inte hämtas igen efter att du lämnat sidan.</p>
      <label className="block text-sm font-bold">Ny åtkomstnyckel<input readOnly value={newKey} autoComplete="off" spellCheck={false} className={`${inputClass} font-mono`} onFocus={(event) => event.currentTarget.select()} /></label>
      <button type="button" onClick={() => setNewKey("")} className="text-sm font-bold underline">Jag har sparat nyckeln – dölj</button>
    </section>}
    <form onSubmit={(event) => {
      event.preventDefault();
      const data = new FormData(event.currentTarget);
      void submit({ command: "create", label: String(data.get("label")), role: String(data.get("role")) as "ADMIN" | "DPO" | "AUDITOR", expires_in_days: Number(data.get("days")) });
    }} className="rounded-sm border border-line bg-panel p-5">
      <fieldset disabled={saving || !!newKey} className="space-y-4">
        <legend className="font-serif text-xl">Skapa åtkomstnyckel</legend>
        <label className="block text-sm font-semibold">Benämning (funktion eller referens)<input name="label" required maxLength={160} className={inputClass} /></label>
        <label className="block text-sm font-semibold">Roll<select name="role" defaultValue="AUDITOR" className={inputClass}>
          <option value="AUDITOR">AUDITOR – läsbehörighet</option><option value="DPO">DPO – styrning och rapporter</option><option value="ADMIN">ADMIN – även åtkomstadministration</option>
        </select></label>
        <label className="block text-sm font-semibold">Giltighet i dagar (1–365)<input name="days" type="number" required min={1} max={365} step={1} defaultValue={90} className={inputClass} /></label>
        <button className="rounded-sm bg-government px-4 py-2 text-sm font-bold text-white">Skapa nyckel</button>
      </fieldset>
    </form>
    <p role="status" aria-live="polite" className="text-sm">{saving ? "Sparar…" : message}</p>
    <section aria-label="Portalens åtkomstnycklar" className="divide-y divide-line rounded-sm border border-line bg-panel px-5">
      {credentials.map((credential) => <article key={credential.id} aria-label={credential.label} className="space-y-2 py-5">
        <h2 className="font-semibold">{credential.label}{credential.current ? " (din nyckel)" : ""}</h2>
        <p className="text-sm">{credential.role} · {credential.status} · Giltig till: {credential.expiresAt}</p>
        <p className="break-all font-mono text-xs text-muted">{credential.id}</p>
        {!credential.current && !credential.revoked && (confirmId === credential.id ? <div className="space-y-3">
          <p className="text-sm">Återkalla {credential.label}? Nyckeln slutar fungera och befintliga sessioner nekas vid nästa skyddade anrop.</p>
          <button disabled={saving} onClick={() => void submit({ command: "revoke", credential_id: credential.id })} className="mr-4 rounded-sm bg-alert px-4 py-2 text-sm font-bold text-white">Bekräfta återkallning</button>
          <button disabled={saving} onClick={() => setConfirmId(null)} className="text-sm underline">Avbryt</button>
        </div> : <button disabled={saving} onClick={() => setConfirmId(credential.id)} className="text-sm font-bold text-government underline">Återkalla</button>)}
      </article>)}
    </section>
  </div>;
}
