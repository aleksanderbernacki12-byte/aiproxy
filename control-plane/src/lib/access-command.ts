import { z } from "zod";

export const accessCommandSchema = z.discriminatedUnion("command", [
  z.object({ command: z.literal("create"), label: z.string().trim().min(1).max(160),
    role: z.enum(["ADMIN", "DPO", "AUDITOR"]), expires_in_days: z.number().int().min(1).max(365) }).strict(),
  z.object({ command: z.literal("revoke"), credential_id: z.uuid() }).strict(),
]);
export type AccessCommand = z.infer<typeof accessCommandSchema>;
