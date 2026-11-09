// Header rules ported from the free checker at https://penetrationtestservices.com/tools/security-headers-checker/
// (Excession Labs, MIT). Rules follow the OWASP Secure Headers Project and MDN.
function cookiesOf(h) {
  if (typeof h.getSetCookie === "function") return h.getSetCookie();
  if (typeof h.getAll === "function") { try { return h.getAll("set-cookie"); } catch {} }
  const v = h.get("set-cookie");
  return v ? [v] : [];
}

const STRICT_REFERRER = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];

function grade(finalUrl, h, startedHttp, redirectedToHttps) {
  const c = [];
  const add = (id, name, status, value, note) => c.push({ id, name, status, value: value ?? null, note });
  const https = finalUrl.protocol === "https:";

  add("https", "HTTPS", https ? "pass" : "fail", finalUrl.protocol.replace(":", ""), https ? (startedHttp ? (redirectedToHttps ? "The http address redirects to https." : "Reached over https.") : "The page is served over https.") : "The final page is served over plain http, so anyone on the network can read or change it.");

  const hsts = h.get("strict-transport-security");
  if (!https) add("hsts", "Strict-Transport-Security", "fail", hsts, "Not applicable until the site uses https.");
  else if (!hsts) add("hsts", "Strict-Transport-Security", "fail", null, "Missing. Browsers may still try http first, which allows a downgrade. OWASP suggests max-age=31536000; includeSubDomains.");
  else {
    const m = /max-age\s*=\s*"?(\d+)/i.exec(hsts);
    const age = m ? Number(m[1]) : 0;
    add("hsts", "Strict-Transport-Security", age >= 31536000 ? "pass" : age > 0 ? "warn" : "fail", hsts, age >= 31536000 ? "Set with max-age of at least one year." : age > 0 ? `max-age is ${age} seconds, under one year (31536000).` : "max-age is missing or zero, which turns HSTS off.");
  }

  const csp = h.get("content-security-policy");
  const cspRo = h.get("content-security-policy-report-only");
  if (!csp) add("csp", "Content-Security-Policy", cspRo ? "warn" : "fail", cspRo ? `Report-Only: ${cspRo}` : null, cspRo ? "Only a Report-Only policy is set. It reports violations but blocks nothing." : "Missing. A policy limits which scripts can run, which reduces the impact of cross-site scripting.");
  else {
    const dir = (name) => { const r = new RegExp(`(?:^|;)\\s*${name}\\s+([^;]*)`, "i").exec(csp); return r ? r[1] : null; };
    const script = dir("script-src") ?? dir("default-src");
    const issues = [];
    if (script == null) issues.push("no script-src or default-src, so scripts are not restricted");
    else {
      const hasNonce = /'nonce-|'sha(256|384|512)-|'strict-dynamic'/i.test(script);
      if (/'unsafe-inline'/i.test(script) && !hasNonce) issues.push("'unsafe-inline' in script-src allows inline scripts");
      if (/'unsafe-eval'/i.test(script)) issues.push("'unsafe-eval' allows eval()");
      if (/(^|\s)(\*|https?:|data:)(\s|$)/i.test(script)) issues.push("a wildcard or scheme source in script-src allows scripts from almost anywhere");
    }
    if (!dir("object-src") && !/default-src\s+'none'/i.test(csp)) issues.push("no object-src (OWASP suggests object-src 'none')");
    add("csp", "Content-Security-Policy", issues.length ? "warn" : "pass", csp, issues.length ? `Set, with gaps: ${issues.join("; ")}.` : "Set, and script sources are restricted.");
  }

  const xfo = (h.get("x-frame-options") || "").trim();
  const fa = csp && /(?:^|;)\s*frame-ancestors\s+([^;]*)/i.exec(csp);
  if (fa) add("framing", "Clickjacking protection", /\*/.test(fa[1]) ? "warn" : "pass", `frame-ancestors ${fa[1].trim()}`, /\*/.test(fa[1]) ? "frame-ancestors allows a wildcard, so most sites can frame this page." : "CSP frame-ancestors controls who can frame the page.");
  else if (/^(deny|sameorigin)$/i.test(xfo)) add("framing", "Clickjacking protection", "pass", `X-Frame-Options: ${xfo}`, "X-Frame-Options stops other sites from framing the page. CSP frame-ancestors is the modern equivalent.");
  else add("framing", "Clickjacking protection", "fail", xfo || null, "Neither CSP frame-ancestors nor X-Frame-Options is set, so another site can load this page in a frame.");

  const xcto = (h.get("x-content-type-options") || "").trim();
  add("nosniff", "X-Content-Type-Options", /^nosniff$/i.test(xcto) ? "pass" : "fail", xcto || null, /^nosniff$/i.test(xcto) ? "Browsers will not guess content types." : "Missing or not nosniff. Browsers may treat a file as a different type, for example run an upload as a script.");

  const rp = (h.get("referrer-policy") || "").trim().toLowerCase();
  const last = rp.split(",").map((s) => s.trim()).filter(Boolean).pop() || "";
  if (!rp) add("referrer", "Referrer-Policy", "warn", null, "Missing. Modern browsers default to strict-origin-when-cross-origin, but setting it keeps older browsers and embedded views in line.");
  else add("referrer", "Referrer-Policy", STRICT_REFERRER.includes(last) ? "pass" : last === "unsafe-url" ? "fail" : "warn", rp, STRICT_REFERRER.includes(last) ? "Full URLs are not sent to other sites." : `${last} can send full URLs, including query strings, to other sites.`);

  const pp = h.get("permissions-policy");
  add("permissions", "Permissions-Policy", pp ? "pass" : "warn", pp, pp ? "Browser features such as camera and geolocation are restricted." : "Missing. It lets you turn off browser features the site does not use, such as camera, microphone and geolocation.");

  const coop = h.get("cross-origin-opener-policy");
  add("coop", "Cross-Origin-Opener-Policy", coop ? (/same-origin/i.test(coop) ? "pass" : "info") : "info", coop, coop ? "Set." : "Not set. same-origin isolates the page from windows it opens or that open it. Check that sign-in pop-ups still work before you add it.");

  const leaks = [];
  const server = h.get("server");
  if (server && /\d/.test(server)) leaks.push(`Server: ${server}`);
  for (const k of ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]) if (h.get(k)) leaks.push(`${k}: ${h.get(k)}`);
  add("leaks", "Version disclosure", leaks.length ? "warn" : "pass", leaks.join("; ") || null, leaks.length ? "These headers tell an attacker which software and version you run. Remove them or drop the version." : "No software versions found in response headers.");

  const acao = h.get("access-control-allow-origin");
  const acac = /true/i.test(h.get("access-control-allow-credentials") || "");
  if (acao) add("cors", "CORS on this page", acao === "*" && !acac ? "info" : acac ? "warn" : "info", `${acao}${acac ? " (with credentials)" : ""}`, acac ? "Credentials are allowed cross-origin. Check that the allowed origin is a fixed list, not a reflection of the request." : "Cross-origin reads are allowed on this page. That is fine for public content.");

  const xxss = h.get("x-xss-protection");
  if (xxss && !/^0/.test(xxss.trim())) add("xxss", "X-XSS-Protection", "info", xxss, "Deprecated. OWASP suggests 0 or leaving it out, and relying on Content-Security-Policy instead.");

  const cookies = cookiesOf(h).slice(0, 20).map((sc) => {
    const [pair, ...attrs] = sc.split(";");
    const a = attrs.map((x) => x.trim().toLowerCase());
    const name = pair.split("=")[0].trim().slice(0, 60);
    const ss = (a.find((x) => x.startsWith("samesite=")) || "").split("=")[1] || null;
    return { name, secure: a.includes("secure"), httponly: a.includes("httponly"), samesite: ss };
  });
  if (cookies.length) {
    const bad = cookies.filter((k) => (https && !k.secure) || !k.samesite);
    add("cookies", "Cookie flags", bad.length ? "warn" : "pass", cookies.map((k) => `${k.name}: ${[k.secure && "Secure", k.httponly && "HttpOnly", k.samesite && `SameSite=${k.samesite}`].filter(Boolean).join(", ") || "no flags"}`).join("; "), bad.length ? `${bad.length} of ${cookies.length} cookies lack Secure or an explicit SameSite. Session cookies also need HttpOnly.` : "Every cookie set here has Secure and SameSite.");
  }
  return { checks: c, cookies };
}


module.exports = { grade, cookiesOf };
