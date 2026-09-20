import { randomUUID, createHash } from "node:crypto";
import pg from "pg";
import { test, expect, type Page } from "@playwright/test";

async function fixture(role = "DPO", organizationId = randomUUID()) {
  const client = new pg.Client({ connectionString: process.env.E2E_DATABASE_URL });
  const key = `e2e-only-${randomUUID()}`;
  await client.connect();
  try {
    await client.query(`INSERT INTO organizations(id,name,tenant_key) VALUES($1,'E2E organization',$2) ON CONFLICT(id) DO NOTHING`, [organizationId, randomUUID()]);
    await client.query(`INSERT INTO dpo_access_keys(organization_id,key_hash,label,role) VALUES($1,$2,'E2E credential',$3)`, [organizationId, createHash("sha256").update(key).digest("hex"), role]);
  } finally { await client.end(); }
  return { key, organizationId };
}
async function login(page: Page, key: string) {
  await page.goto("/login");
  await page.getByLabel("Åtkomstnyckel", { exact: true }).fill(key);
  await page.getByRole("button", { name: "Logga in", exact: true }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
}
test("login rejects invalid credentials and logout protects dashboard", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("Åtkomstnyckel", { exact: true }).fill("invalid-e2e-key");
  await page.getByRole("button", { name: "Logga in", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Ogiltig åtkomstnyckel." })).toHaveText("Ogiltig åtkomstnyckel.");
  await login(page, (await fixture()).key);
  await page.getByRole("button", { name: "Logga ut" }).click();
  await page.goto("/dashboard");
  await expect(page).toHaveURL(/\/login$/);
});
for (const role of ["DPO", "ADMIN"]) {
  test(`${role} saves profiles and retention with auditable legal holds`, async ({ page }) => {
    await login(page, (await fixture(role)).key);
    await page.getByRole("link", { name: "Systemprofiler", exact: true }).last().click();
    for (const [label, value] of Object.entries({ "Applikations-ID": "e2e-app", "Modell": "e2e-model", "Systemnamn": "E2E assistant", "Systemansvarig funktion": "Compliance", "Avsett användningsområde": "Test review", "Rättslig grund": "TEST-17", "Mänsklig tillsyn": "Mandatory review" })) {
      await page.getByLabel(label, { exact: true }).fill(value);
    }
    await page.getByRole("button", { name: "Spara profil" }).click();
    await expect(page).toHaveURL(/systems\?id=/);
    await page.reload();
    await expect(page.getByLabel("Systemnamn", { exact: true })).toHaveValue("E2E assistant");
    await page.getByLabel("Systemnamn", { exact: true }).fill("Updated E2E assistant");
    await page.getByRole("button", { name: "Spara profil" }).click();
    await expect(page.getByRole("status")).toContainText("sparats");
    await page.goto("/dashboard");
    await page.getByRole("link", { name: "Lagring", exact: true }).click();
    await page.getByLabel("Lagringstid i dagar (30–3650)").fill("365");
    await page.getByRole("button", { name: "Spara lagringstid" }).click();
    await expect(page.getByText("Lagringstid: 365 dagar", { exact: true })).toBeVisible();
    await page.getByLabel("Ärendereferens eller skäl (utan personuppgifter)").fill("E2E-CASE");
    await page.getByRole("button", { name: "Aktivera bevarandestopp" }).click();
    await expect(page.getByText("Bevarandestopp: Aktivt", { exact: true })).toBeVisible();
    await page.getByLabel("Lagringstid i dagar (30–3650)").fill("730");
    await page.getByRole("button", { name: "Spara lagringstid" }).click();
    await expect(page.getByText("Lagringstid: 730 dagar", { exact: true })).toBeVisible();
    await page.reload();
    await expect(page.getByText("Bevarandestopp: Aktivt", { exact: true })).toBeVisible();
    await page.getByLabel("Ärendereferens eller skäl (utan personuppgifter)").fill("E2E-CASE closed");
    await page.getByRole("button", { name: "Häv bevarandestopp" }).click();
    await expect(page.getByText("Bevarandestopp: Inaktivt", { exact: true })).toBeVisible();
    await page.goto("/dashboard/audit");
    await expect(page.getByRole("cell", { name: "LEGAL_HOLD_RELEASED", exact: true })).toBeVisible();
    await expect(page.getByRole("cell", { name: "AI_SYSTEM_PROFILE_UPSERTED", exact: true }).first()).toBeVisible();
  });
}
test("auditor cannot write and another organization cannot see profiles", async ({ page }) => {
  const owner = await fixture();
  // Seed through the real authenticated endpoint to keep schema and audit behavior intact.
  await login(page, owner.key);
  const response = await page.request.post("/api/dashboard/systems", { headers: { origin: "http://localhost:32187" }, data: {
    application_id: "private", model: "model", name: "Private profile", provider: "", intended_purpose: "Test", risk_class: "LIMITED", system_owner: "Test", legal_basis: "Test", human_oversight: "Test", data_categories: [], deployment_regions: [], status: "ACTIVE",
  } });
  expect(response.ok()).toBeTruthy();
  const { id } = await response.json();
  await login(page, (await fixture("AUDITOR", owner.organizationId)).key);
  await page.goto(`/dashboard/systems?id=${id}`);
  await expect(page.getByLabel("Systemnamn", { exact: true })).toBeDisabled();
  expect((await page.request.post("/api/dashboard/retention", { headers: { origin: "http://localhost:32187" }, data: { command: "set", days: 365 } })).status()).toBe(403);
  await page.goto("/dashboard/retention");
  await expect(page.getByRole("button", { name: "Spara lagringstid" })).toHaveCount(0);
  await login(page, (await fixture("ADMIN")).key);
  await page.goto("/dashboard/systems");
  await expect(page.getByRole("link", { name: "Private profile", exact: true })).toHaveCount(0);
  await page.goto(`/dashboard/systems?id=${id}`);
  // Next.js may have started streaming a 200 response before notFound().
  await expect(page.getByRole("heading", { name: "404", exact: true })).toBeVisible();
  await expect(page.getByLabel("Systemnamn", { exact: true })).toHaveCount(0);
});

test("admin creates portal access once and revocation invalidates an existing session", async ({ page, browser }) => {
  const admin = await fixture("ADMIN");
  await login(page, admin.key);
  await page.getByRole("link", { name: "Åtkomst", exact: true }).last().click();
  await expect(page.getByRole("article").filter({ hasText: "(din nyckel)" }).getByRole("button", { name: "Återkalla", exact: true })).toHaveCount(0);
  await page.getByLabel("Benämning (funktion eller referens)").fill("E2E reviewer");
  await page.getByRole("combobox", { name: "Roll", exact: true }).selectOption("AUDITOR");
  await page.getByRole("button", { name: "Skapa nyckel", exact: true }).click();
  const keyInput = page.getByRole("textbox", { name: "Ny åtkomstnyckel", exact: true });
  await expect(keyInput).toBeVisible();
  const key = await keyInput.inputValue();
  expect(key.length).toBeGreaterThanOrEqual(32);
  const reviewerContext = await browser.newContext({ baseURL: "http://localhost:32187" });
  const reviewer = await reviewerContext.newPage();
  try {
    await login(reviewer, key);
    await reviewer.goto("/dashboard/access");
    await expect(reviewer.getByText("Endast administratörer har tillgång till denna sida.", { exact: true })).toBeVisible();
    expect((await reviewer.request.post("http://localhost:32187/api/dashboard/access", {
      headers: { origin: "http://localhost:32187" }, data: { command: "create", label: "unauthorized", role: "ADMIN", expires_in_days: 30 },
    })).status()).toBe(403);
    await page.getByRole("button", { name: "Jag har sparat nyckeln – dölj" }).click();
    await page.reload();
    await expect(keyInput).toHaveCount(0);
    const row = page.getByRole("article", { name: "E2E reviewer", exact: true });
    const credentialId = await row.locator("p.font-mono").innerText();
    const outsider = await fixture("ADMIN");
    await login(reviewer, outsider.key);
    expect((await reviewer.request.post("/api/dashboard/access", { headers: { origin: "http://localhost:32187" },
      data: { command: "revoke", credential_id: credentialId } })).status()).toBe(409);
    await login(reviewer, key);
    await row.getByRole("button", { name: "Återkalla", exact: true }).click();
    await row.getByRole("button", { name: "Bekräfta återkallning" }).click();
    await expect(row).toContainText("Återkallad");
    await reviewer.goto("/dashboard");
    await expect(reviewer).toHaveURL(/\/login$/);
    await reviewer.getByLabel("Åtkomstnyckel", { exact: true }).fill(key);
    await reviewer.getByRole("button", { name: "Logga in", exact: true }).click();
    await expect(reviewer.getByRole("alert").filter({ hasText: "Ogiltig åtkomstnyckel." })).toBeVisible();
    await page.goto("/dashboard/audit");
    await expect(page.getByRole("cell", { name: "DPO_CREDENTIAL_CREATED", exact: true })).toBeVisible();
    await expect(page.getByRole("cell", { name: "DPO_CREDENTIAL_REVOKED", exact: true })).toBeVisible();
    await login(page, (await fixture("ADMIN")).key);
    await page.goto("/dashboard/access");
    await expect(page.getByRole("article", { name: "E2E reviewer", exact: true })).toHaveCount(0);
  } finally { await reviewerContext.close(); }
});
