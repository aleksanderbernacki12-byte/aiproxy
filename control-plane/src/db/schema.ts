import {
  bigint,
  bigserial,
  index,
  integer,
  jsonb,
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

export const telemetryPublicKeys = pgTable("telemetry_public_keys", {
  keyId: varchar("key_id", { length: 64 }).primaryKey(),
  publicKeyPem: text("public_key_pem").notNull(),
  label: varchar("label", { length: 160 }),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
});

export const telemetryEventIds = pgTable("telemetry_event_ids", {
  eventId: uuid("event_id").primaryKey(),
  receivedAt: timestamp("received_at", { withTimezone: true }).defaultNow().notNull(),
});

export const telemetryBuffer = pgTable(
  "telemetry_buffer",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    eventId: uuid("event_id")
      .notNull()
      .references(() => telemetryEventIds.eventId),
    eventTimestamp: timestamp("event_timestamp", { withTimezone: true }).notNull(),
    keyId: varchar("key_id", { length: 64 }).notNull(),
    payload: jsonb("payload").$type<TelemetryEvent>().notNull(),
    receivedAt: timestamp("received_at", { withTimezone: true }).defaultNow().notNull(),
    processingAttempts: integer("processing_attempts").default(0).notNull(),
    lastError: text("last_error"),
  },
  (table) => [
    uniqueIndex("telemetry_buffer_event_id_idx").on(table.eventId),
    index("telemetry_buffer_chain_order_idx").on(
      table.keyId,
      table.eventTimestamp,
      table.receivedAt,
      table.id,
    ),
  ],
);

export const telemetryChainHeads = pgTable("telemetry_chain_heads", {
  keyId: varchar("key_id", { length: 64 }).primaryKey(),
  latestEventHash: varchar("latest_event_hash", { length: 64 }).notNull(),
  sequence: bigint("sequence", { mode: "bigint" }).notNull(),
  lastEventTimestamp: timestamp("last_event_timestamp", { withTimezone: true }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
});

export const telemetryEvents = pgTable(
  "telemetry_events",
  {
    id: bigserial("id", { mode: "bigint" }).primaryKey(),
    eventId: uuid("event_id")
      .notNull()
      .references(() => telemetryEventIds.eventId),
    eventTimestamp: timestamp("event_timestamp", { withTimezone: true }).notNull(),
    clientIdHash: varchar("client_id_hash", { length: 64 }).notNull(),
    applicationId: varchar("application_id", { length: 160 }).notNull(),
    routing: jsonb("routing").$type<Record<string, unknown>>().notNull(),
    complianceFlags: jsonb("compliance_flags").$type<string[]>().notNull(),
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
    uniqueIndex("telemetry_events_event_id_idx").on(table.eventId),
    index("telemetry_events_chain_idx").on(table.keyId, table.chainSequence),
    index("telemetry_events_status_timestamp_idx").on(
      table.status,
      table.eventTimestamp,
    ),
  ],
);
