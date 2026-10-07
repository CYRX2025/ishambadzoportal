// POST /.netlify/functions/paynow-init
// Body (JSON): { reference, amount, additionalinfo, returnurl, resulturl,
//                authemail?, authphone?, authname?, redirect? }
// Phone-only checkout: when authemail is missing but authphone is given,
// a placeholder "client_<digits>@placeholder.com" email is generated so
// Paynow Express Checkout gets BOTH authemail + authphone.
// Hash rule (per docs): EVERY sent field except "hash", concatenated in
// field order, + key, SHA512, uppercase hex — so optional fields ARE hashed.
// Env: PAYNOW_INTEGRATION_ID, PAYNOW_INTEGRATION_KEY (required).
// Docs: https://developers.paynow.co.zw/docs/paynow/initiate_transaction/
//       https://developers.paynow.co.zw/docs/paynow/generating_hash/
// Normalise a phone to digits only, e.g. "+263 71 234 5678" -> "263712345678".
function normPhone(phone) {
  return String(phone || "").replace(/\D/g, "").slice(0, 20);
}
const crypto = require("crypto");

const GATEWAY =
  process.env.PAYNOW_GATEWAY ||
  "https://www.paynow.co.zw/interface/initiatetransaction";
const FALLBACK_RETURN = process.env.PAYNOW_RETURN_URL || "/";
const FALLBACK_RESULT = process.env.PAYNOW_RESULT_URL || "/";

function json(statusCode, obj) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
    },
    body: JSON.stringify(obj),
  };
}

function redirect(to) {
  return {
    statusCode: 302,
    headers: {
      Location: to,
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
    },
    body: "",
  };
}

/* Parse Paynow url-encoded text, e.g.
 * "Status=Ok&BrowserUrl=https%3A%2F%2F...&PollUrl=...&Hash=ABC..."
 * Keys lowercased; values kept encoded, decoded once when hashed. */
function parseResponseText(text) {
  const raw = {};
  const order = [];
  String(text || "")
    .split("&")
    .forEach((pair) => {
      const i = pair.indexOf("=");
      if (i === -1) return;
      const k = pair.slice(0, i).trim().toLowerCase();
      const v = pair.slice(i + 1).trim();
      if (!k || k in raw) return;
      raw[k] = v;
      order.push(k);
    });
  const dec = (s) => decodeURIComponent(String(s).replace(/\+/g, "%20"));
  const get = (k) => (raw[k] !== undefined ? dec(raw[k]) : "");
  return {
    raw, order,
    status: get("status"),
    browserurl: get("browserurl"),
    pollurl: get("pollurl"),
    paynowreference: get("paynowreference"),
    error: get("error"),
    hash: (raw["hash"] || "").toUpperCase(),
  };
}

/* Validate inbound hash: decoded values (except hash) in received order
 * + key, SHA512, uppercase hex. See /docs/paynow/validating_hash/. */
function validResponseHash(parsed, integrationKey) {
  if (!parsed.hash) return false;
  const dec = (s) => decodeURIComponent(String(s).replace(/\+/g, "%20"));
  const concat =
    parsed.order
      .filter((k) => k !== "hash")
      .map((k) => dec(parsed.raw[k]))
      .join("") + integrationKey;
  const calc = crypto
    .createHash("sha512")
    .update(concat, "utf8")
    .digest("hex")
    .toUpperCase();
  return calc === parsed.hash;
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
      body: "",
    };
  }
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  const ID = process.env.PAYNOW_INTEGRATION_ID;
  const KEY = process.env.PAYNOW_INTEGRATION_KEY;
  if (!ID || !KEY) {
    return json(500, {
      error: "Paynow is not configured. Set PAYNOW_INTEGRATION_ID and PAYNOW_INTEGRATION_KEY in Netlify env.",
    });
  }

  let body = {};
  try {
    body = JSON.parse(event.body || "{}");
  } catch (e) {
    return json(400, { error: "Invalid JSON body" });
  }

  const reference = String(body.reference || "").slice(0, 64);
  const amount = Number(body.amount);
  if (!reference || !isFinite(amount) || amount <= 0) {
    return json(400, { error: "reference and a positive amount are required" });
  }
  const amountStr = amount.toFixed(2);
  const additionalinfo = String(body.additionalinfo || "ishambadzo token top-up").slice(0, 255);
  const returnurl = String(body.returnurl || FALLBACK_RETURN);
  const resulturl = String(body.resulturl || FALLBACK_RESULT);

  const out = await initTransaction(
    { reference, amountStr, additionalinfo, returnurl, resulturl,
      authemail: body.authemail, authphone: body.authphone, authname: body.authname },
    { id: ID, key: KEY, gateway: GATEWAY }
  );
  if (!out.ok) return json(out.http || 502, { error: out.error, responseText: out.responseText });

  const wantRedirect =
    (event.queryStringParameters && event.queryStringParameters.redirect === "1") ||
    body.redirect === true || body.redirect === "1";
  if (wantRedirect) return redirect(out.browserurl);

  return json(200, {
    status: out.status, browserurl: out.browserurl, pollurl: out.pollurl,
    paynowreference: out.paynowreference, hashValid: true,
    reference, amount: amountStr,
    authemail: out.authemail, authphone: out.authphone,
    authemailGenerated: out.authemailGenerated,
  });
};

async function initTransaction(p, creds) {
  // Phone-only checkout: missing/empty authemail + a usable phone ->
  // generate "client_<digits>@placeholder.com" so Express Checkout gets BOTH.
  const phone = normPhone(p.authphone);
  let email = String(p.authemail || "").trim().slice(0, 128);
  const emailGenerated = !email && !!phone;
  if (emailGenerated) {
    email = "client_" + phone + "@placeholder.com";
  }
  // Build ordered field list; request hash covers EVERY sent field except
  // "hash" (concatenated in field order + key). Optional authemail/authphone/
  // authname MUST be hashed when sent, else Paynow rejects with hash mismatch.
  const fields = [
    ["id", String(creds.id)],
    ["reference", p.reference],
    ["amount", p.amountStr],
    ["additionalinfo", p.additionalinfo],
    ["returnurl", p.returnurl],
    ["resulturl", p.resulturl],
    ["status", "Message"],
  ];
  if (email) fields.push(["authemail", email]);
  if (phone) fields.push(["authphone", phone]);
  if (p.authname) fields.push(["authname", String(p.authname).slice(0, 128)]);
  const requestHash = crypto
    .createHash("sha512")
    .update(fields.map((f) => f[1]).join("") + creds.key, "utf8")
    .digest("hex")
    .toUpperCase();
  const form = new URLSearchParams();
  fields.forEach((f) => form.set(f[0], f[1]));
  form.set("hash", requestHash);

  let responseText = "";
  try {
    const res = await fetch(creds.gateway, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    responseText = await res.text();
  } catch (e) {
    return { ok: false, http: 502, error: "Could not reach Paynow: " + (e && e.message ? e.message : e) };
  }
  const parsed = parseResponseText(responseText);
  if (parsed.status.toLowerCase() !== "ok" || !parsed.browserurl) {
    return { ok: false, http: 502, error: parsed.error || "Paynow rejected the transaction", responseText };
  }
  if (!validResponseHash(parsed, creds.key)) {
    return { ok: false, http: 502, error: "Paynow response hash mismatch. Transaction NOT started.", responseText };
  }
  return { ok: true, status: parsed.status, browserurl: parsed.browserurl,
    pollurl: parsed.pollurl, paynowreference: parsed.paynowreference,
    authemail: email || null, authphone: phone || null,
    authemailGenerated: emailGenerated };
}

exports.parseResponseText = parseResponseText;
exports.validResponseHash = validResponseHash;
exports.initTransaction = initTransaction;
exports.normPhone = normPhone;

