import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";

const scramIterations = 4096;

// A client-side SCRAM-SHA-256 verifier keeps the plaintext password out of
// server statement logs, which managed PostgreSQL often records for DDL.
function scramVerifier(password) {
  const salt = randomBytes(16);
  const saltedPassword = pbkdf2Sync(password, salt, scramIterations, 32, "sha256");
  const clientKey = createHmac("sha256", saltedPassword).update("Client Key").digest();
  const storedKey = createHash("sha256").update(clientKey).digest();
  const serverKey = createHmac("sha256", saltedPassword).update("Server Key").digest();
  return `SCRAM-SHA-256$${scramIterations}:${salt.toString("base64")}$${storedKey.toString("base64")}:${serverKey.toString("base64")}`;
}

// Creates or updates the role the application logs in as. It holds no
// privileges of its own (NOINHERIT) and only gains them by switching to the
// application role from 0019, so a failed switch denies every query instead
// of running without row-level security.
export async function ensureApplicationLogin(client, password) {
  // Printable ASCII only: PostgreSQL normalises other passwords (SASLprep)
  // before hashing, which this verifier does not.
  if (!/^[\x21-\x7e]{32,}$/.test(password)) {
    throw new Error("APP_DATABASE_PASSWORD must be at least 32 printable ASCII characters without spaces");
  }
  // Readable so deployments can put it in their connection string; unique
  // because database names are unique within a cluster.
  const { rows: [{ login_role: loginRole, app_role: appRole }] } = await client.query(`
    SELECT current_database() || '_login' AS login_role,
           'aiproxy_app_' || left(md5(current_database()), 12) AS app_role`);
  if (loginRole.length > 63) throw new Error(`Login role name ${loginRole} exceeds PostgreSQL's 63 characters`);
  // Never take over an unrelated role that happens to have this name; the
  // owner and superusers also count as members, so check the exact shape.
  const { rows: [existing] } = await client.query(`
    SELECT NOT login.rolinherit AND NOT login.rolsuper AND NOT login.rolcreaterole AND EXISTS (
      SELECT 1 FROM pg_auth_members membership JOIN pg_roles app ON app.oid = membership.roleid
      WHERE membership.member = login.oid AND app.rolname = $2) AS ours
    FROM pg_roles login WHERE login.rolname = $1`, [loginRole, appRole]);
  if (existing && !existing.ours) throw new Error(`Role ${loginRole} exists and is not this database's login role`);
  const login = client.escapeIdentifier(loginRole);
  const setPassword = (literal) => client.query(existing
    ? `ALTER ROLE ${login} PASSWORD ${literal}`
    : `CREATE ROLE ${login} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE PASSWORD ${literal}`);
  try {
    await setPassword(client.escapeLiteral(scramVerifier(password)));
  } catch (error) {
    // Neon forwards role changes to its own control plane, which rejects
    // verifiers; the server then hashes the plaintext itself.
    if (!/only supports being given plaintext passwords/.test(error?.message ?? "")) throw error;
    await setPassword(client.escapeLiteral(password));
  }
  await client.query(`GRANT ${client.escapeIdentifier(appRole)} TO ${login}`);
  return loginRole;
}
