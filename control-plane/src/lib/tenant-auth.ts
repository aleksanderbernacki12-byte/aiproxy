import "server-only";

import { createHash } from "node:crypto";
import { eq } from "drizzle-orm";
import { organizations } from "@/db/schema";
import { getDatabase } from "@/db/client";

export type AuthenticatedOrganization = {
  id: string;
  name: string;
};

export function extractBearerToken(request: Request) {
  const authorization = request.headers.get("authorization") ?? "";
  const match = /^Bearer ([^\s]+)$/.exec(authorization);
  return match?.[1] ?? null;
}

export function digestTenantKey(tenantKey: string) {
  return createHash("sha256").update(tenantKey, "utf8").digest("hex");
}

export async function authenticateTenant(
  request: Request,
): Promise<AuthenticatedOrganization | null> {
  const tenantKey = extractBearerToken(request);
  if (!tenantKey) {
    return null;
  }
  const digest = digestTenantKey(tenantKey);
  const [organization] = await getDatabase()
    .select({ id: organizations.id, name: organizations.name })
    .from(organizations)
    .where(eq(organizations.tenantKey, digest))
    .limit(1);
  return organization ?? null;
}
