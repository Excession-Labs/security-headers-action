"use strict";
// Fetches one URL (one GET per redirect hop, headers only) and grades the final response.
const { grade } = require("./grade");

const UA = "ExcessionLabsHeadersAction/1.0 (+https://github.com/Excession-Labs/security-headers-action)";
const MAX_REDIRECTS = 5;

function parseTarget(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return { error: "Not a valid URL. Use a full address such as https://example.com" };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { error: "Only http and https URLs can be checked." };
  if (u.username || u.password) return { error: "Remove the user name and password from the URL." };
  u.hash = "";
  return { url: u };
}

async function fetchHop(u, timeoutMs) {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const r = await fetch(u.toString(), {
      method: "GET",
      redirect: "manual",
      signal: ac.signal,
      headers: { "user-agent": UA, accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5" },
    });
    try { await r.body?.cancel(); } catch {}
    return r;
  } finally {
    clearTimeout(t);
  }
}

async function checkUrl(raw, opts = {}) {
  const timeoutMs = (opts.timeoutSeconds ?? 8) * 1000;
  const ignore = new Set(opts.ignore || []);
  const v = parseTarget(String(raw || "").trim());
  if (v.error) return { url: raw, ok: false, error: v.error };
  let u = v.url;
  const startedHttp = u.protocol === "http:";
  const hops = [];
  let r;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    try {
      r = await fetchHop(u, timeoutMs);
    } catch (e) {
      const secs = timeoutMs / 1000;
      return { url: raw, ok: false, error: e?.name === "AbortError" ? `No answer within ${secs} seconds.` : `Could not reach the site (${e?.cause?.code || e?.message || "network error"}).`, hops };
    }
    hops.push({ url: u.toString(), status: r.status });
    const loc = r.headers.get("location");
    if (r.status >= 300 && r.status < 400 && loc) {
      if (i === MAX_REDIRECTS) return { url: raw, ok: false, error: `More than ${MAX_REDIRECTS} redirects.`, hops };
      const next = parseTarget(new URL(loc, u).toString());
      if (next.error) return { url: raw, ok: false, error: `A redirect points to an address that cannot be checked: ${next.error}`, hops };
      u = next.url;
      continue;
    }
    break;
  }
  const redirectedToHttps = startedHttp && u.protocol === "https:";
  const g = grade(u, r.headers, startedHttp, redirectedToHttps);
  const checks = g.checks.filter((c) => !ignore.has(c.id));
  const count = (s) => checks.filter((x) => x.status === s).length;
  const summary = { pass: count("pass"), warn: count("warn"), fail: count("fail"), info: count("info") };
  return {
    url: raw,
    ok: true,
    final_url: u.toString(),
    status: r.status,
    hops,
    result: summary.fail ? "fail" : summary.warn ? "warn" : "pass",
    summary,
    checks,
  };
}

module.exports = { checkUrl, parseTarget, MAX_REDIRECTS };
