import { z } from "zod";

export const riskClasses = ["UNCLASSIFIED", "MINIMAL", "LIMITED", "HIGH", "PROHIBITED"] as const;
export const systemStatuses = ["ACTIVE", "SUSPENDED", "RETIRED"] as const;
export const riskLabels = { UNCLASSIFIED: "Ej klassificerad", MINIMAL: "Minimal", LIMITED: "Begränsad", HIGH: "Hög", PROHIBITED: "Förbjuden" };
export const statusLabels = { ACTIVE: "Aktiv", SUSPENDED: "Pausad", RETIRED: "Avvecklad" };
const text = (max: number) => z.string().trim().min(1).max(max);
export const aiSystemProfileSchema = z.object({
  application_id: text(160), model: text(160), name: text(200),
  provider: z.string().trim().max(160), intended_purpose: text(4000),
  risk_class: z.enum(riskClasses), system_owner: text(200),
  legal_basis: text(4000), human_oversight: text(4000),
  data_categories: z.array(text(160)).max(30),
  deployment_regions: z.array(text(160)).max(30),
  status: z.enum(systemStatuses),
}).strict();
export type AISystemProfile = z.infer<typeof aiSystemProfileSchema>;
