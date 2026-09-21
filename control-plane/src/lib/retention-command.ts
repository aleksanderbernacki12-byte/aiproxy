import { z } from "zod";

export const retentionCommandSchema = z.discriminatedUnion("command", [
  z.object({ command: z.literal("set"), days: z.number().int().min(30).max(3650) }).strict(),
  z.object({ command: z.literal("hold"), reason: z.string().trim().min(1).max(500) }).strict(),
  z.object({ command: z.literal("release"), reason: z.string().trim().min(1).max(500) }).strict(),
]);
export type RetentionCommand = z.infer<typeof retentionCommandSchema>;
