// POST /.netlify/functions/paynow-hash
// Body: { reference, amount, additionalinfo, returnurl, resulturl }
// Returns: { id, reference, amount, additionalinfo, returnurl, resulturl, status, hash }
// The Integration Key NEVER leaves the server: hash = UPPERCASE(SHA512(
//   id + reference + amount + additionalinfo + returnurl + resulturl + status + integrationKey ))
// Field order follows https://developers.paynow.co.zw/docs/paynow/generating_hash/
const crypto = require("crypto");

// Where Paynow sends the customer back after paying (swap for your live URLs).
const FALLBACK_RETURN = process.env.PAYNOW_RETURN_URL || "/";
const FALLBACK_RESULT = process.env.PAYNOW_RESULT_URL || "/";

function json(statusCode, obj) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    body: JSON.stringify(obj),
  };
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
  if (!process.env.PAYNOW_INTEGRATION_ID || !process.env.PAYNOW_INTEGRATION_KEY) {
    return json(500, {
      error:
        "Paynow is not configured on the server. Set PAYNOW_INTEGRATION_ID and PAYNOW_INTEGRATION_KEY in Netlify environment variables.",
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
  const status = "Message";
  // Official formula: raw values concatenated IN FIELD ORDER, key appended, SHA512, uppercase hex.
  const raw = process.env.PAYNOW_INTEGRATION_ID + reference + amountStr + additionalinfo + returnurl + resulturl + status + process.env.PAYNOW_INTEGRATION_KEY;
  const hash = crypto.createHash("sha512").update(raw, "utf8").digest("hex").toUpperCase();
  return json(200, {
    id: process.env.PAYNOW_INTEGRATION_ID,
    reference,
    amount: amountStr,
    additionalinfo,
    returnurl,
    resulturl,
    status,
    hash,
    gateway: "https://www.paynow.co.zw/interface/initiatetransaction",
  });
};
