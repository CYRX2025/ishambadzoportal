// GET /.netlify/functions/paynow-status?pollurl=<url>&reference=<ref>
// Polls Paynow for an express (remotetransaction) payment status.
// Returns { paid, status, amount, reference, paynowreference }.
// paid=true only when Paynow reports status "Paid".
// Env: PAYNOW_INTEGRATION_ID, PAYNOW_INTEGRATION_KEY (to verify hash).
const crypto = require("crypto");

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

function parsePairs(text) {
  const out = {};
  const order = [];
  const values = {};
  String(text || "")
    .split("&")
    .forEach((pair) => {
      const i = pair.indexOf("=");
      if (i === -1) return;
      const k = pair.slice(0, i).trim().toLowerCase();
      if (!k) return;
      let v = pair.slice(i + 1).trim();
      try {
        v = decodeURIComponent(v.replace(/\+/g, "%20"));
      } catch (e) { /* keep raw */ }
      if (!(k in out)) {
        out[k] = v;
        order.push(k);
        values[k] = v;
      }
    });
  out._order = order;
  out._values = values;
  return out;
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
      body: "",
    };
  }
  const q = event.queryStringParameters || {};
  const pollurl = String(q.pollurl || "");
  const reference = String(q.reference || "").slice(0, 64);
  if (!pollurl || !/^https:\/\/([a-z0-9-]+\.)*paynow\.co\.zw\//i.test(pollurl)) {
    return json(400, { error: "A valid Paynow pollurl is required." });
  }
  const KEY = process.env.PAYNOW_INTEGRATION_KEY || "";
  let text = "";
  try {
    const res = await fetch(pollurl, { method: "GET" });
    text = await res.text();
  } catch (e) {
    return json(502, { error: "Could not reach Paynow: " + (e && e.message ? e.message : e) });
  }
  const p = parsePairs(text);
  const status = p.status || "";
  // Verify hash: concat of field values in received order + key, SHA512 UPPER.
  let hashValid = null;
  if (KEY && p.hash) {
    const concat =
      p._order.filter((k) => k !== "hash").map((k) => p._values[k]).join("") + KEY;
    try {
      hashValid =
        crypto.createHash("sha512").update(concat, "utf8").digest("hex").toUpperCase() ===
        String(p.hash).toUpperCase();
    } catch (e) {
      hashValid = false;
    }
  }
  // Only credit on Paid AND a hash that doesn't contradict the key.
  const paid = /^paid$/i.test(String(status).trim()) && hashValid !== false;
  return json(200, {
    paid, status: status || "Unknown", reference,
    amount: p.amount || null, paynowreference: p.paynowreference || null,
    hashValid,
  });
};
