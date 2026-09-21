import "server-only";
import { asc, eq, sql } from "drizzle-orm";
import { getDatabase } from "@/db/client";
import { aiSystems } from "@/db/schema";
import type { AISystemProfile } from "./ai-system-profile";

export async function listAISystems(organizationId: string) {
  return getDatabase().select().from(aiSystems).where(eq(aiSystems.organizationId, organizationId))
    .orderBy(asc(aiSystems.name), asc(aiSystems.id));
}

export async function saveAISystem(identity: { organizationId: string; credentialId: string }, profile: AISystemProfile) {
  return getDatabase().transaction(async (tx) => {
    const values = {
      organizationId: identity.organizationId, applicationId: profile.application_id,
      model: profile.model, name: profile.name, provider: profile.provider || null,
      intendedPurpose: profile.intended_purpose, riskClass: profile.risk_class,
      systemOwner: profile.system_owner, legalBasis: profile.legal_basis,
      humanOversight: profile.human_oversight, dataCategories: profile.data_categories,
      deploymentRegions: profile.deployment_regions, status: profile.status,
    };
    const [saved] = await tx.insert(aiSystems).values(values).onConflictDoUpdate({
      target: [aiSystems.organizationId, aiSystems.applicationId, aiSystems.model],
      set: { ...values, updatedAt: new Date() },
    }).returning({ id: aiSystems.id });
    await tx.execute(sql`SELECT append_security_audit_event(
      ${identity.organizationId}::uuid, 'DPO_CREDENTIAL', ${identity.credentialId},
      'AI_SYSTEM_PROFILE_UPSERTED', 'AI_SYSTEM', ${saved.id},
      ${JSON.stringify({ application_id: profile.application_id, model: profile.model, risk_class: profile.risk_class, status: profile.status })}::jsonb
    )`);
    return saved.id;
  });
}
