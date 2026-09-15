import { readFile } from "node:fs/promises";
import process from "node:process";
import pg from "pg";

const [, , organizationId, applicationId, model, filename] = process.argv;
if (!organizationId || !applicationId || !model || !filename) {
  throw new Error("Usage: npm run systems:upsert -- <organization-id> <application-id> <model> <profile.json>");
}
if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
const profile = JSON.parse(await readFile(filename, "utf8"));
const allowed = new Set(["name", "provider", "intended_purpose", "risk_class", "system_owner", "legal_basis", "human_oversight", "data_categories", "deployment_regions", "status"]);
for (const field of Object.keys(profile)) if (!allowed.has(field)) throw new Error(`Unknown profile field: ${field}`);
const required = ["name", "intended_purpose", "system_owner", "legal_basis", "human_oversight"];
for (const field of required) {
  if (typeof profile[field] !== "string" || !profile[field].trim()) throw new Error(`${field} must be a non-empty string`);
}
if (applicationId.length > 160 || model.length > 160 || profile.name.length > 200 || profile.system_owner.length > 200) throw new Error("AI system identity field is too long");
const riskClasses = ["UNCLASSIFIED", "MINIMAL", "LIMITED", "HIGH", "PROHIBITED"];
const statuses = ["ACTIVE", "SUSPENDED", "RETIRED"];
if (!riskClasses.includes(profile.risk_class ?? "UNCLASSIFIED")) throw new Error("risk_class is invalid");
if (!statuses.includes(profile.status ?? "ACTIVE")) throw new Error("status is invalid");
for (const field of ["data_categories", "deployment_regions"]) {
  if (!Array.isArray(profile[field] ?? []) || (profile[field] ?? []).some((value) => typeof value !== "string" || !value.trim())) {
    throw new Error(`${field} must be an array of non-empty strings`);
  }
}
if (profile.provider != null && (typeof profile.provider !== "string" || !profile.provider.trim())) throw new Error("provider must be a non-empty string");

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
try {
  await client.connect();
  const result = await client.query(
    `INSERT INTO ai_systems (
       organization_id, application_id, model, name, provider, intended_purpose,
       risk_class, system_owner, legal_basis, human_oversight, data_categories,
       deployment_regions, status
     ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13)
     ON CONFLICT (organization_id, application_id, model) DO UPDATE SET
       name=EXCLUDED.name, provider=EXCLUDED.provider, intended_purpose=EXCLUDED.intended_purpose,
       risk_class=EXCLUDED.risk_class, system_owner=EXCLUDED.system_owner,
       legal_basis=EXCLUDED.legal_basis, human_oversight=EXCLUDED.human_oversight,
       data_categories=EXCLUDED.data_categories, deployment_regions=EXCLUDED.deployment_regions,
       status=EXCLUDED.status, updated_at=now()
     RETURNING id`,
    [organizationId, applicationId, model, profile.name.trim(), profile.provider?.trim() ?? null,
      profile.intended_purpose.trim(), profile.risk_class ?? "UNCLASSIFIED", profile.system_owner.trim(),
      profile.legal_basis.trim(), profile.human_oversight.trim(), JSON.stringify(profile.data_categories ?? []),
      JSON.stringify(profile.deployment_regions ?? []), profile.status ?? "ACTIVE"],
  );
  console.log(`AI system profile: ${result.rows[0].id}`);
} finally { await client.end(); }
