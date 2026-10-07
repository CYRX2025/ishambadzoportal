// POST /.netlify/functions/paynow-init
// SIGN-AND-RETURN ONLY — never POSTs to Paynow itself. The browser must
// POST the signed payload straight to the gateway via an auto-submitting
// form so Paynow can set its session cookies (server-side fetch breaks
// this and causes "Please login using Guest Payment" errors).
// Body (JSON): { reference, amount, additionalinfo, returnurl, resulturl,
//                authemail?, authphone?, authname? }
// Phone-only checkout: missing/empty authemail + usable authphone ->
// placeholder "client_<digits>@placeholder.com" is generated AND returned.
// Returns JSON: { id, reference, amount, additionalinfo, returnurl,
//   resulturl, status, authemail?, authphone?, authname?,
//   authemailGenerated, hash, gateway }
// The browser then builds a hidden form and submits it to gateway.
// Hash rule (per docs): EVERY returned field except "hash", concatenated
// in field order, + key, SHA512, uppercase hex.
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
  const signed = signPayload(
    { reference, amountStr, additionalinfo, returnurl, resulturl,
      authemail: body.authemail, authphone: body.authphone, authname: body.authname },
    { id: ID, key: KEY }
  );
  return json(200, {
    id: ID, reference, amount: amountStr, additionalinfo, returnurl, resulturl,
    status: "Message", hash: signed.hash, gateway: GATEWAY,
    ...(signed.authemail ? { authemail: signed.authemail } : {}),
    ...(signed.authphone ? { authphone: signed.authphone } : {}),
    ...(signed.authname ? { authname: signed.authname } : {}),
    authemailGenerated: signed.authemailGenerated,
  });
};

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

/* parseResponseText/validResponseHash: kept for the resulturl/poll
 * verification path (inbound Paynow status updates), NOT for init. */

exports.parseResponseText = parseResponseText;
exports.validResponseHash = validResponseHash;
exports.signPayload = signPayload;
exports.normPhone = normPhone;

