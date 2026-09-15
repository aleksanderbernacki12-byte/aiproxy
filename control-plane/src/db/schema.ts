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

export const organizations = pgTable("organizations", {
  id: uuid("id").defaultRandom().primaryKey(),
  name: varchar("name", { length: 160 }).notNull(),
  // Stores SHA-256(tenant key), never the bearer credential itself.
  tenantKey: varchar("tenant_key", { length: 64 }).notNull().unique(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

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
