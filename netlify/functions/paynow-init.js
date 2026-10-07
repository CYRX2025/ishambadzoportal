// POST /.netlify/functions/paynow-init
// TWO MODES (mode auto-selected):
//  1. SIGN-AND-RETURN (default, browser form-POST to initiatetransaction):
//     Body: { reference, amount, additionalinfo, returnurl, resulturl,
//             authemail?, authphone?, authname? }
//     Returns the complete signed payload as JSON; the browser submits it
//     via a hidden auto-posting form so Paynow sets its session cookies.
//     NOTE: this is ALWAYS the guest-checkout page — authemail/authphone
//     only PRE-FILL the form; they never skip it.
//  2. ECOCASH EXPRESS (server-side remotetransaction, no Paynow page at all):
//     Body: { ..., method:"ecocash", phone:"077...", authemail:"user@x.com" }
//     Server POSTs to /interface/remotetransaction; Paynow pushes a USSD
//     prompt to the handset. Returns { ok:true, pollurl, paynowreference,
//     instructions } — frontend shows instructions + polls paynow-status.
//     Docs: https://developers.paynow.co.zw/docs/paynow/express_checkout_transactions/
//           https://developers.paynow.co.zw/docs/paynow/initiate_mobile_transaction/
// Env: PAYNOW_INTEGRATION_ID, PAYNOW_INTEGRATION_KEY (required).
//      PAYNOW_GATEWAY (init override), PAYNOW_REMOTE_GATEWAY (remote override),
//      PAYNOW_RETURN_URL / PAYNOW_RESULT_URL (fallbacks).
// Normalise a phone to digits only, e.g. "+263 71 234 5678" -> "263712345678".
function normPhone(phone) {
  return String(phone || "").replace(/\D/g, "").slice(0, 20);
}
const crypto = require("crypto");

const GATEWAY =
  process.env.PAYNOW_GATEWAY ||
  "https://www.paynow.co.zw/interface/initiatetransaction";
const REMOTE_GATEWAY =
  process.env.PAYNOW_REMOTE_GATEWAY ||
  "https://www.paynow.co.zw/interface/remotetransaction";
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
  const method = String(body.method || "").trim().toLowerCase();

  // MODE 2: EcoCash express — server-side remotetransaction (USSD push,
  // no Paynow page). Requires a real customer email + the wallet number.
  if (method === "ecocash" || method === "onemoney") {
    const expressEmail = String(body.authemail || "").trim().slice(0, 128);
    const expressPhone = normPhone(body.phone || body.authphone);
    if (!expressEmail || expressEmail.indexOf("@") === -1) {
      return json(400, {
        error: "A valid email address (authemail) is required for EcoCash express checkout.",
        mode: "express",
      });
    }
    if (!expressPhone) {
      return json(400, {
        error: "A valid EcoCash number (phone) is required for express checkout.",
        mode: "express",
      });
    }
    const out = await remoteTransaction(
      { reference, amountStr, additionalinfo, returnurl, resulturl,
        authemail: expressEmail, phone: expressPhone, method },
      { id: ID, key: KEY, gateway: REMOTE_GATEWAY }
    );
    if (!out.ok) return json(out.http || 502, { error: out.error, mode: "express", responseText: out.responseText });
    return json(200, {
      ok: true, mode: "express", status: out.status, reference,
      amount: amountStr, pollurl: out.pollurl,
      paynowreference: out.paynowreference, instructions: out.instructions,
    });
  }

  // MODE 1 (default): sign-and-return for the browser guest-checkout form.
  const signed = signPayload(
    { reference, amountStr, additionalinfo, returnurl, resulturl,
      authemail: body.authemail, authphone: body.authphone, authname: body.authname },
    { id: ID, key: KEY }
  );
  return json(200, {
    mode: "form", id: ID, reference, amount: amountStr, additionalinfo, returnurl, resulturl,
    status: "Message", hash: signed.hash, gateway: GATEWAY,
    ...(signed.authemail ? { authemail: signed.authemail } : {}),
    ...(signed.authphone ? { authphone: signed.authphone } : {}),
    ...(signed.authname ? { authname: signed.authname } : {}),
    authemailGenerated: signed.authemailGenerated,
  });
};

/* MODE 2: server-side EcoCash/OneMoney express via remotetransaction.
 * Field order: base fields + authemail + phone + method, ALL hashed.
 * Returns instructions for the user + pollurl (NO browser redirect). */
async function remoteTransaction(p, creds) {
  const fields = [
    ["id", String(creds.id)],
    ["reference", p.reference],
    ["amount", p.amountStr],
    ["additionalinfo", p.additionalinfo],
    ["returnurl", p.returnurl],
    ["resulturl", p.resulturl],
    ["authemail", p.authemail],
    ["phone", p.phone],
    ["method", p.method],
    ["status", "Message"],
  ];
  const hash = crypto
    .createHash("sha512")
    .update(fields.map((f) => f[1]).join("") + creds.key, "utf8")
    .digest("hex")
    .toUpperCase();
  const form = new URLSearchParams();
  fields.forEach((f) => form.set(f[0], f[1]));
  form.set("hash", hash);

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
  if (parsed.status.toLowerCase() === "error" || !parsed.pollurl) {
    return { ok: false, http: 502, error: parsed.error || "Paynow rejected the express transaction", responseText };
  }
  if (!validResponseHash(parsed, creds.key)) {
    return { ok: false, http: 502, error: "Paynow response hash mismatch. Transaction NOT started.", responseText };
  }
  return { ok: true, status: parsed.status, pollurl: parsed.pollurl,
    paynowreference: parsed.paynowreference,
    instructions: parsed.raw.instructions
      ? decodeURIComponent(String(parsed.raw.instructions).replace(/\+/g, "%20"))
      : "Approve the payment on your phone." };
}

/* Pure sign-and-return: build the ordered field list (incl. the
 * phone-fallback email), hash EVERY field except "hash" in order + key. */
function signPayload(p, creds) {
  const phone = normPhone(p.authphone);
  let email = String(p.authemail || "").trim().slice(0, 128);
  const authemailGenerated = !email && !!phone;
  if (authemailGenerated) email = "client_" + phone + "@placeholder.com";
  const authname = String(p.authname || "").trim().slice(0, 128);
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
  if (authname) fields.push(["authname", authname]);
  const hash = crypto
    .createHash("sha512")
    .update(fields.map((f) => f[1]).join("") + creds.key, "utf8")
    .digest("hex")
    .toUpperCase();
  return { fields, hash, authemail: email || null, authphone: phone || null,
    authname: authname || null, authemailGenerated };
}

/* parseResponseText/validResponseHash: used to verify the remotetransaction
 * response AND any inbound Paynow status-update / resulturl messages. */

exports.parseResponseText = parseResponseText;
exports.validResponseHash = validResponseHash;
exports.signPayload = signPayload;
exports.remoteTransaction = remoteTransaction;
exports.normPhone = normPhone;

