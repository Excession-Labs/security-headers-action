"use strict";
const test = require("node:test");
const assert = require("node:assert");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { checkUrl } = require("../src/check");
const { grade } = require("../src/grade");
const stop = (s) => { s.closeAllConnections?.(); s.close(); };

const GOOD = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'none'; script-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=()",
  "cross-origin-opener-policy": "same-origin",
};

function serve(handler) {
  return new Promise((resolve) => {
    const s = http.createServer(handler);
    s.listen(0, "127.0.0.1", () => resolve({ s, base: `http://127.0.0.1:${s.address().port}` }));
  });
}
const withHeaders = (h, status = 200) => (req, res) => { res.writeHead(status, h); res.end("body"); };
const byId = (r, id) => r.checks.find((c) => c.id === id);

test("good headers pass every header check; plain http fails the https check", async () => {
  const { s, base } = await serve(withHeaders(GOOD));
  const r = await checkUrl(base + "/");
  stop(s);
  assert.equal(r.ok, true);
  for (const id of ["csp", "framing", "nosniff", "referrer", "permissions", "coop", "leaks"]) assert.equal(byId(r, id).status, "pass", id);
  assert.equal(byId(r, "https").status, "fail");
  assert.equal(byId(r, "hsts").status, "fail"); // HSTS does not apply over plain http
  assert.equal(r.result, "fail");
});

test("ignore removes a check from the result", async () => {
  const { s, base } = await serve(withHeaders(GOOD));
  const r = await checkUrl(base, { ignore: ["https", "hsts"] });
  stop(s);
  assert.equal(byId(r, "https"), undefined);
  assert.equal(r.result, "pass");
});

test("missing headers fail or warn as the rules say", async () => {
  const { s, base } = await serve(withHeaders({}));
  const r = await checkUrl(base);
  stop(s);
  assert.equal(byId(r, "hsts").status, "fail");
  assert.equal(byId(r, "csp").status, "fail");
  assert.equal(byId(r, "framing").status, "fail");
  assert.equal(byId(r, "nosniff").status, "fail");
  assert.equal(byId(r, "referrer").status, "warn");
  assert.equal(byId(r, "permissions").status, "warn");
  assert.equal(byId(r, "coop").status, "info");
});

test("HSTS grading over https: one year passes, shorter warns, zero or missing fails", () => {
  const st = (v) => grade(new URL("https://x.example/"), new Headers(v ? { "strict-transport-security": v } : {}), false, false).checks.find((c) => c.id === "hsts").status;
  assert.equal(st("max-age=31536000; includeSubDomains"), "pass");
  assert.equal(st("max-age=3600"), "warn");
  assert.equal(st("max-age=0"), "fail");
  assert.equal(st(null), "fail");
  assert.equal(grade(new URL("https://x.example/"), new Headers(), true, false).checks[0].status, "pass");
});

test("CSP: report-only warns, unsafe-inline and unsafe-eval warn, nonce allows inline", async () => {
  let h;
  const { s, base } = await serve((q, res) => { res.writeHead(200, h); res.end(); });
  h = { "content-security-policy-report-only": "default-src 'self'" };
  assert.equal(byId(await checkUrl(base), "csp").status, "warn");
  h = { "content-security-policy": "default-src 'none'; script-src 'self' 'unsafe-inline'" };
  assert.equal(byId(await checkUrl(base), "csp").status, "warn");
  h = { "content-security-policy": "default-src 'none'; script-src 'self' 'unsafe-eval'" };
  assert.match(byId(await checkUrl(base), "csp").note, /unsafe-eval/);
  h = { "content-security-policy": "script-src 'nonce-abc' 'unsafe-inline'; object-src 'none'" };
  assert.equal(byId(await checkUrl(base), "csp").status, "pass");
  stop(s);
});

test("framing: X-Frame-Options passes, wildcard frame-ancestors warns", async () => {
  let h;
  const { s, base } = await serve((q, res) => { res.writeHead(200, h); res.end(); });
  h = { "x-frame-options": "DENY" };
  assert.equal(byId(await checkUrl(base), "framing").status, "pass");
  h = { "content-security-policy": "default-src 'none'; frame-ancestors *" };
  assert.equal(byId(await checkUrl(base), "framing").status, "warn");
  stop(s);
});

test("referrer-policy: unsafe-url fails, no-referrer-when-downgrade warns", async () => {
  let h;
  const { s, base } = await serve((q, res) => { res.writeHead(200, h); res.end(); });
  h = { "referrer-policy": "unsafe-url" };
  assert.equal(byId(await checkUrl(base), "referrer").status, "fail");
  h = { "referrer-policy": "no-referrer-when-downgrade" };
  assert.equal(byId(await checkUrl(base), "referrer").status, "warn");
  stop(s);
});

test("version disclosure, CORS with credentials and X-XSS-Protection", async () => {
  const { s, base } = await serve(withHeaders({
    server: "nginx/1.25.3",
    "x-powered-by": "Express",
    "access-control-allow-origin": "https://a.example",
    "access-control-allow-credentials": "true",
    "x-xss-protection": "1; mode=block",
  }));
  const r = await checkUrl(base);
  stop(s);
  assert.equal(byId(r, "leaks").status, "warn");
  assert.match(byId(r, "leaks").value, /nginx\/1\.25\.3/);
  assert.equal(byId(r, "cors").status, "warn");
  assert.equal(byId(r, "xxss").status, "info");
});

test("cookie flags are graded per cookie", async () => {
  const { s, base } = await serve((q, res) => {
    res.writeHead(200, { "set-cookie": ["a=1; HttpOnly", "b=2; Secure; SameSite=Lax"] });
    res.end();
  });
  const r = await checkUrl(base);
  stop(s);
  assert.equal(byId(r, "cookies").status, "warn");
  assert.match(byId(r, "cookies").note, /1 of 2/);
});

test("redirects are followed; more than 5 redirects is an error", async () => {
  const { s, base } = await serve((req, res) => {
    if (req.url === "/loop") { res.writeHead(302, { location: "/loop" }); return res.end(); }
    if (req.url === "/a") { res.writeHead(301, { location: "/b" }); return res.end(); }
    res.writeHead(200, GOOD); res.end();
  });
  const ok = await checkUrl(base + "/a", { ignore: ["https", "hsts"] });
  assert.equal(ok.hops.length, 2);
  assert.ok(ok.final_url.endsWith("/b"));
  assert.equal(ok.result, "pass");
  const bad = await checkUrl(base + "/loop");
  stop(s);
  assert.equal(bad.ok, false);
  assert.match(bad.error, /More than 5 redirects/);
});

test("exactly 5 redirects are allowed", async () => {
  const { s, base } = await serve((req, res) => {
    const n = Number(req.url.slice(1)) || 0;
    if (n < 5) { res.writeHead(302, { location: `/${n + 1}` }); return res.end(); }
    res.writeHead(200, GOOD); res.end();
  });
  const r = await checkUrl(base + "/0");
  stop(s);
  assert.equal(r.ok, true);
  assert.equal(r.hops.length, 6);
});

test("timeout and unreachable and bad input give errors", async () => {
  const { s, base } = await serve(() => {});
  const t = await checkUrl(base, { timeoutSeconds: 0.3 });
  assert.equal(t.ok, false);
  assert.match(t.error, /No answer/);
  stop(s);
  const u = await checkUrl("http://127.0.0.1:1/");
  assert.equal(u.ok, false);
  assert.equal((await checkUrl("ftp://example.com")).ok, false);
  assert.equal((await checkUrl("not a url")).ok, false);
});

// Runs src/index.js the way the runner does: INPUT_ variables, GITHUB_OUTPUT and GITHUB_STEP_SUMMARY files.
function runAction(inputs) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sha-"));
  const out = path.join(dir, "output"), sum = path.join(dir, "summary");
  fs.writeFileSync(out, ""); fs.writeFileSync(sum, "");
  const env = { PATH: process.env.PATH, GITHUB_OUTPUT: out, GITHUB_STEP_SUMMARY: sum };
  for (const [k, v] of Object.entries(inputs)) env[`INPUT_${k.toUpperCase().replace(/ /g, "_")}`] = v;
  return new Promise((resolve) => {
    const p = require("node:child_process").spawn(process.execPath, [path.join(__dirname, "../src/index.js")], { env });
    let stdout = "";
    p.stdout.on("data", (d) => (stdout += d));
    p.on("close", (code) => resolve({ code, stdout, output: fs.readFileSync(out, "utf8"), summary: fs.readFileSync(sum, "utf8") }));
  });
}

test("entry point: fail-on=fail exits 1 for a bad server and writes outputs and summary", async () => {
  const { s, base } = await serve(withHeaders({}));
  const r = await runAction({ urls: base, "fail-on": "fail" });
  stop(s);
  assert.equal(r.code, 1);
  assert.match(r.output, /^summary<<EOF_/m);
  assert.match(r.output, /^result<<EOF_\w+\nfail\n/m);
  const json = JSON.parse(/summary<<(EOF_\w+)\n([\s\S]*?)\n\1\n/.exec(r.output)[2]);
  assert.equal(json.totals.fail, 1);
  assert.equal(json.results[0].checks.find((c) => c.id === "hsts").status, "fail");
  assert.match(r.summary, /## HTTP security headers/);
  assert.match(r.summary, /\| Strict-Transport-Security \| FAIL \|/);
  assert.match(r.stdout, /::error title=Strict-Transport-Security::/);
});

test("entry point: fail-on=none exits 0; fail-on=warn exits 1 on warnings only; ignore works", async () => {
  const { s, base } = await serve(withHeaders((() => { const h = { ...GOOD }; delete h["permissions-policy"]; return h; })()));
  const none = await runAction({ urls: base, "fail-on": "none" });
  assert.equal(none.code, 0);
  const onlyFail = await runAction({ urls: base, ignore: "https, hsts" });
  assert.equal(onlyFail.code, 0);
  const warn = await runAction({ urls: base, "fail-on": "warn", ignore: "https, hsts" });
  assert.equal(warn.code, 1);
  const clean = await runAction({ urls: base, "fail-on": "warn", ignore: "https, hsts, permissions" });
  stop(s);
  assert.equal(clean.code, 0);
});

test("entry point: several URLs, comments and bad input", async () => {
  const a = await serve(withHeaders(GOOD));
  const b = await serve(withHeaders({}));
  const r = await runAction({ urls: `# staging\n${a.base}\n\n${b.base}\n`, "fail-on": "none" });
  stop(a.s); stop(b.s);
  assert.equal(r.code, 0);
  const json = JSON.parse(/summary<<(EOF_\w+)\n([\s\S]*?)\n\1\n/.exec(r.output)[2]);
  assert.equal(json.totals.urls, 2);
  assert.equal((await runAction({ urls: "" })).code, 1);
  assert.equal((await runAction({ urls: "http://127.0.0.1:1", "fail-on": "maybe" })).code, 1);
  assert.equal((await runAction({ urls: "http://127.0.0.1:1/", "fail-on": "fail", timeout: "2" })).code, 1);
  assert.equal((await runAction({ urls: "http://127.0.0.1:1/", "fail-on": "none" })).code, 0);
});
