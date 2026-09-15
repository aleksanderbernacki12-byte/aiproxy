import {
  bigint,
  bigserial,
  foreignKey,
  index,
  integer,
  jsonb,
  primaryKey,
  pgEnum,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";
import type { TelemetryEvent } from "@/lib/telemetry/schema";

export const telemetryVerificationStatus = pgEnum(
  "telemetry_verification_status",
  ["VERIFIED", "INVALID_SIGNATURE", "COMPROMISED_CHAIN"],
);

export const dpoRole = pgEnum("dpo_role", ["ADMIN", "DPO", "AUDITOR"]);
export const merkleAnchorStatus = pgEnum("merkle_anchor_status", ["PENDING", "ANCHORED"]);
export const aiRiskClass = pgEnum("ai_risk_class", ["UNCLASSIFIED", "MINIMAL", "LIMITED", "HIGH", "PROHIBITED"]);
export const aiSystemStatus = pgEnum("ai_system_status", ["ACTIVE", "SUSPENDED", "RETIRED"]);

export const organizations = pgTable("organizations", {
  id: uuid("id").defaultRandom().primaryKey(),
  name: varchar("name", { length: 160 }).notNull(),
  // Legacy digest retained for migration compatibility; authentication uses tenantAccessKeys.
  tenantKey: varchar("tenant_key", { length: 64 }).notNull().unique(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const tenantAccessKeys = pgTable(
  "tenant_access_keys",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id").notNull().references(() => organizations.id),
    keyHash: varchar("key_hash", { length: 64 }).notNull().unique(),
    label: varchar("label", { length: 160 }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [index("tenant_access_keys_organization_idx").on(table.organizationId, table.revokedAt, table.expiresAt)],
);

export const aiSystems = pgTable(
  "ai_systems",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id").notNull().references(() => organizations.id),
    applicationId: varchar("application_id", { length: 160 }).notNull(),
    model: varchar("model", { length: 160 }).notNull(),
    name: varchar("name", { length: 200 }).notNull(),
    provider: varchar("provider", { length: 160 }),
    intendedPurpose: text("intended_purpose").notNull(),
    riskClass: aiRiskClass("risk_class").default("UNCLASSIFIED").notNull(),
    systemOwner: varchar("system_owner", { length: 200 }).notNull(),
    legalBasis: text("legal_basis").notNull(),
    humanOversight: text("human_oversight").notNull(),
    dataCategories: jsonb("data_categories").$type<string[]>().default([]).notNull(),
    deploymentRegions: jsonb("deployment_regions").$type<string[]>().default([]).notNull(),
    status: aiSystemStatus("status").default("ACTIVE").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("ai_systems_identity_idx").on(table.organizationId, table.applicationId, table.model),
    index("ai_systems_organization_risk_idx").on(table.organizationId, table.riskClass, table.status),
  ],
);

export const dpoAccessKeys = pgTable(
  "dpo_access_keys",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id").notNull().references(() => organizations.id),
    keyHash: varchar("key_hash", { length: 64 }).notNull().unique(),
    label: varchar("label", { length: 160 }).notNull(),
    role: dpoRole("role").default("DPO").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [index("dpo_access_keys_organization_idx").on(table.organizationId, table.revokedAt)],
);

export const complianceReports = pgTable(
  "compliance_reports",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id").notNull().references(() => organizations.id),
    generatedBy: uuid("generated_by").notNull().references(() => dpoAccessKeys.id),
    payload: jsonb("payload").$type<Record<string, unknown>>().notNull(),
    payloadHash: varchar("payload_hash", { length: 64 }).notNull(),
    signatureAlgorithm: varchar("signature_algorithm", { length: 32 }).notNull(),
    signingKeyId: varchar("signing_key_id", { length: 64 }).notNull(),
    signature: text("signature").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [index("compliance_reports_organization_created_idx").on(table.organizationId, table.createdAt, table.id)],
);

export const reportSigningKeys = pgTable("report_signing_keys", {
  keyId: varchar("key_id", { length: 64 }).primaryKey(),
  publicKeyPem: text("public_key_pem").notNull(),
  firstUsedAt: timestamp("first_used_at", { withTimezone: true }).defaultNow().notNull(),
  lastUsedAt: timestamp("last_used_at", { withTimezone: true }).defaultNow().notNull(),
}, (table) => [index("report_signing_keys_last_used_idx").on(table.lastUsedAt, table.keyId)]);

export const telemetryPublicKeys = pgTable(
  "telemetry_public_keys",
  {
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id),
    keyId: varchar("key_id", { length: 64 }).notNull(),
    publicKeyPem: text("public_key_pem").notNull(),
    label: varchar("label", { length: 160 }),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    validFrom: timestamp("valid_from", { withTimezone: true }),
    validUntil: timestamp("valid_until", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    revokedReason: varchar("revoked_reason", { length: 240 }),
  },
  (table) => [primaryKey({ columns: [table.organizationId, table.keyId] })],
);

export const telemetryEventIds = pgTable(
  "telemetry_event_ids",
  {
    eventId: uuid("event_id").notNull(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id),
    receivedAt: timestamp("received_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [primaryKey({ columns: [table.organizationId, table.eventId] })],
);

export const telemetryBuffer = pgTable(
  "telemetry_buffer",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id),
    eventId: uuid("event_id").notNull(),
    eventTimestamp: timestamp("event_timestamp", { withTimezone: true }).notNull(),
    keyId: varchar("key_id", { length: 64 }).notNull(),
    payload: jsonb("payload").$type<TelemetryEvent>().notNull(),
    receivedAt: timestamp("received_at", { withTimezone: true }).defaultNow().notNull(),
    processingAttempts: integer("processing_attempts").default(0).notNull(),
    lastError: text("last_error"),
  },
  (table) => [
    uniqueIndex("telemetry_buffer_event_id_idx").on(table.organizationId, table.eventId),
    foreignKey({
      columns: [table.organizationId, table.eventId],
      foreignColumns: [telemetryEventIds.organizationId, telemetryEventIds.eventId],
    }),
    index("telemetry_buffer_chain_order_idx").on(
      table.organizationId,
      table.keyId,
      table.eventTimestamp,
      table.receivedAt,
      table.id,
    ),
  ],
);

export const telemetryChainHeads = pgTable(
  "telemetry_chain_heads",
  {
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id),
    keyId: varchar("key_id", { length: 64 }).notNull(),
    latestEventHash: varchar("latest_event_hash", { length: 64 }).notNull(),
    sequence: bigint("sequence", { mode: "bigint" }).notNull(),
    lastEventTimestamp: timestamp("last_event_timestamp", { withTimezone: true }).notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [primaryKey({ columns: [table.organizationId, table.keyId] })],
);

export type MerkleCheckpointHead = { key_id: string; event_hash: string; sequence: string };

export const telemetryMerkleCheckpoints = pgTable(
  "telemetry_merkle_checkpoints",
  {
    id: bigserial("id", { mode: "bigint" }).primaryKey(),
    organizationId: uuid("organization_id").notNull().references(() => organizations.id),
    rootHash: varchar("root_hash", { length: 64 }).notNull(),
    leafCount: integer("leaf_count").notNull(),
    chainHeads: jsonb("chain_heads").$type<MerkleCheckpointHead[]>().notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    anchorStatus: merkleAnchorStatus("anchor_status").default("PENDING").notNull(),
    anchorAttempts: integer("anchor_attempts").default(0).notNull(),
    anchorLastError: text("anchor_last_error"),
    anchorId: varchar("anchor_id", { length: 240 }),
    anchoredAt: timestamp("anchored_at", { withTimezone: true }),
    anchorReceipt: jsonb("anchor_receipt").$type<Record<string, unknown>>(),
  },
  (table) => [
    uniqueIndex("telemetry_merkle_checkpoints_root_idx").on(table.organizationId, table.rootHash),
    index("telemetry_merkle_checkpoints_latest_idx").on(table.organizationId, table.createdAt, table.id),
  ],
);

export const telemetryEvents = pgTable(
  "telemetry_events",
  {
    id: bigserial("id", { mode: "bigint" }).primaryKey(),
    organizationId: uuid("organization_id")
      .notNull()
      .references(() => organizations.id),
    eventId: uuid("event_id").notNull(),
    eventTimestamp: timestamp("event_timestamp", { withTimezone: true }).notNull(),
    clientIdHash: varchar("client_id_hash", { length: 64 }).notNull(),
    applicationId: varchar("application_id", { length: 160 }).notNull(),
    routing: jsonb("routing").$type<Record<string, unknown>>().notNull(),
    complianceFlags: jsonb("compliance_flags").$type<Record<string, boolean>>().notNull(),
    metrics: jsonb("metrics").$type<Record<string, unknown>>().notNull(),
    hashAlgorithm: varchar("hash_algorithm", { length: 32 }).notNull(),
    requestResponseHash: varchar("request_response_hash", { length: 64 }).notNull(),
    previousEventHash: varchar("previous_event_hash", { length: 64 }).notNull(),
    eventHash: varchar("event_hash", { length: 64 }).notNull(),
    signatureAlgorithm: varchar("signature_algorithm", { length: 64 }).notNull(),
    keyId: varchar("key_id", { length: 64 }).notNull(),
    signature: text("signature").notNull(),
    status: telemetryVerificationStatus("status").notNull(),
    statusReason: text("status_reason"),
    chainSequence: bigint("chain_sequence", { mode: "bigint" }),
    receivedAt: timestamp("received_at", { withTimezone: true }).notNull(),
    processedAt: timestamp("processed_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (table) => [
    uniqueIndex("telemetry_events_event_id_idx").on(table.organizationId, table.eventId),
    foreignKey({
      columns: [table.organizationId, table.eventId],
      foreignColumns: [telemetryEventIds.organizationId, telemetryEventIds.eventId],
    }),
    index("telemetry_events_chain_idx").on(
      table.organizationId,
      table.keyId,
      table.chainSequence,
    ),
    index("telemetry_events_status_timestamp_idx").on(
      table.status,
      table.eventTimestamp,
    ),
  ],
);
