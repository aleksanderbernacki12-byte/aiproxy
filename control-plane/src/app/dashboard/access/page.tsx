import Link from "next/link";
import { requireDashboardIdentity } from "@/lib/dashboard-auth";
import { listAccessCredentials } from "@/lib/access-admin";
import { AccessManager } from "@/components/access-manager";

export default async function AccessPage() {
  const identity = await requireDashboardIdentity();
  if (identity.role !== "ADMIN") return <div className="space-y-5 p-5 sm:p-8"><h1 className="font-serif text-3xl">Åtkomstadministration</h1><p>Endast administratörer har tillgång till denna sida.</p><Link href="/dashboard" className="underline">Till AI-inventeringen</Link></div>;
  const credentials = await listAccessCredentials(identity);
  return <div className="space-y-7 p-5 sm:p-8">
    <Link href="/dashboard" className="text-sm text-government underline">Till AI-inventeringen</Link>
    <header><h1 className="font-serif text-3xl">Åtkomstadministration</h1><p className="mt-2 text-sm text-muted">Hantera organisationens portalåtkomst. Använd funktioner och referenser i benämningar, inte personuppgifter. Den egna nyckeln kan inte återkallas här.</p></header>
    <AccessManager credentials={credentials.map((credential) => ({
      id: credential.id, label: credential.label, role: credential.role,
      current: credential.id === identity.credentialId, revoked: !!credential.revoked_at,
      status: credential.revoked_at ? "Återkallad" : credential.expired ? "Utgången" : "Aktiv",
      expiresAt: credential.expires_at ? new Date(credential.expires_at).toISOString() : "Ingen tidsgräns",
    }))} />
  </div>;
}
