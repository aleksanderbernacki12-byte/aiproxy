import { createHash, createPrivateKey, sign, timingSafeEqual } from "node:crypto";

// Demo stand-in for the independent append-only anchor the Control Plane
// requires. It signs receipts but stores nothing, so it proves the protocol,
// not independence: a real deployment uses a separately operated ledger.
const receiptDomain = Buffer.from("aiproxy-merkle-anchor-receipt-v1\0");

// RFC 8785 for a flat object of strings: keys sorted, JSON string escaping.
function canonical(receipt) {
  return `{${Object.keys(receipt).sort().map((key) => `${JSON.stringify(key)}:${JSON.stringify(receipt[key])}`).join(",")}}`;
}

export function signReceipt(checkpoint, privateKeyPem, anchoredAt = new Date()) {
  const receipt = {
    // Derived from the checkpoint so a retried request returns the same ID.
    anchor_id: `demo-${createHash("sha256").update(`${checkpoint.checkpoint_id}:${checkpoint.root_hash}`).digest("hex").slice(0, 32)}`,
    checkpoint_id: checkpoint.checkpoint_id,
    root_hash: checkpoint.root_hash,
    anchored_at: anchoredAt.toISOString(),
    signature_algorithm: "Ed25519",
    signature: "",
  };
  const bytes = Buffer.concat([receiptDomain, Buffer.from(canonical(receipt))]);
  receipt.signature = sign(null, bytes, createPrivateKey(privateKeyPem)).toString("base64");
  return receipt;
}

function authorized(header, token) {
  const expected = Buffer.from(`Bearer ${token}`);
  const actual = Buffer.from(header ?? "");
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

export async function POST(request) {
  const token = process.env.ANCHOR_TOKEN ?? "";
  const privateKey = (process.env.ANCHOR_PRIVATE_KEY ?? "").replaceAll("\\n", "\n");
  if (token.length < 32 || !privateKey) return Response.json({ error: "anchor is not configured" }, { status: 503 });
  if (!authorized(request.headers.get("authorization"), token)) return Response.json({ error: "unauthorized" }, { status: 401 });
  let checkpoint;
  try {
    checkpoint = await request.json();
  } catch {
    return Response.json({ error: "invalid JSON" }, { status: 400 });
  }
  if (typeof checkpoint?.checkpoint_id !== "string" || !/^[1-9][0-9]*$/.test(checkpoint.checkpoint_id)
    || typeof checkpoint.root_hash !== "string" || !/^[a-f0-9]{64}$/.test(checkpoint.root_hash)) {
    return Response.json({ error: "invalid checkpoint" }, { status: 400 });
  }
  return Response.json(signReceipt(checkpoint, privateKey));
}
