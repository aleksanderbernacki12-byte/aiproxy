import { z } from "zod";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256 = /^[0-9a-f]{64}$/;
const RAW_BASE64 = /^[A-Za-z0-9+/]+$/;
const MAX_BATCH_SIZE = 500;

const jsonPrimitive = z.union([z.string(), z.number().finite(), z.boolean(), z.null()]);
export const jsonValueSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    jsonPrimitive,
    z.array(jsonValueSchema).max(256),
    z.record(z.string().max(128), jsonValueSchema),
  ]),
);

const metadataObject = z
  .record(z.string().min(1).max(128), jsonValueSchema)
  .refine((value) => Object.keys(value).length <= 128, "Too many metadata fields");

export const cryptographySchema = z
  .object({
    hash_algorithm: z.literal("SHA-256"),
    request_response_hash: z.string().regex(SHA256),
    previous_event_hash: z.union([z.literal(""), z.string().regex(SHA256)]),
    event_hash: z.string().regex(SHA256),
    signature_algorithm: z.literal("ECDSA_P256_SHA256_ASN1"),
    key_id: z.string().regex(SHA256),
    signature: z.string().min(8).max(256).regex(RAW_BASE64),
  })
  .strict();

export const telemetryEventSchema = z
  .object({
    event_id: z.string().regex(UUID),
    timestamp: z.iso.datetime({ offset: true }),
    client_id_hash: z.string().regex(SHA256),
    application_id: z.string().min(1).max(160),
    routing: metadataObject,
    compliance_flags: z.array(z.string().min(1).max(128)).max(128),
    metrics: metadataObject,
    cryptography: cryptographySchema,
  })
  .strict();

export const telemetryBatchSchema = z
  .union([telemetryEventSchema, z.array(telemetryEventSchema).min(1).max(MAX_BATCH_SIZE)])
  .transform((value) => (Array.isArray(value) ? value : [value]))
  .superRefine((events, context) => {
    const ids = new Set<string>();
    for (const [index, event] of events.entries()) {
      if (ids.has(event.event_id)) {
        context.addIssue({
          code: "custom",
          message: "Duplicate event_id in request batch",
          path: [index, "event_id"],
        });
      }
      ids.add(event.event_id);
    }
  });

export type TelemetryEvent = z.infer<typeof telemetryEventSchema>;
