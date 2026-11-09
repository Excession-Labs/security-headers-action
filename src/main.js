"use strict";
const fs = require("node:fs");
const { checkUrl } = require("./check");

// The runner passes each input as INPUT_<NAME>, upper-cased, spaces turned into underscores.
// Hyphens stay, so "fail-on" arrives as INPUT_FAIL-ON. Accept both spellings.
function getInput(name, env = process.env) {
  const key = `INPUT_${name.toUpperCase().replace(/ /g, "_")}`;
  const alt = key.replace(/-/g, "_");
  return String(env[key] ?? env[alt] ?? "").trim();
}

const ICON = { pass: "PASS", warn: "WARN", fail: "FAIL", info: "INFO" };
const cell = (s) => String(s ?? "").replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

function markdown(results, failOn) {
  const lines = ["## HTTP security headers", ""];
  lines.push("| URL | Result | Pass | Warn | Fail |", "| --- | --- | --- | --- | --- |");
  for (const r of results) {
    if (!r.ok) lines.push(`| ${cell(r.url)} | ERROR | - | - | - |`);
    else lines.push(`| ${cell(r.url)} | ${r.result.toUpperCase()} | ${r.summary.pass} | ${r.summary.warn} | ${r.summary.fail} |`);
  }
  for (const r of results) {
    lines.push("", `### ${cell(r.url)}`, "");
    if (!r.ok) { lines.push(`Error: ${r.error}`); continue; }
    if (r.final_url !== new URL(r.url).toString()) lines.push(`Final URL: ${r.final_url} (HTTP ${r.status})`, "");
    lines.push("| Check | Status | Value | Note |", "| --- | --- | --- | --- |");
    for (const c of r.checks) lines.push(`| ${cell(c.name)} | ${ICON[c.status]} | ${cell(c.value ? `\`${String(c.value).slice(0, 120).replace(/`/g, "'")}\`` : "")} | ${cell(c.note)} |`);
  }
  lines.push("", `Fail-on setting: \`${failOn}\`. Headers only; this is not a penetration test.`);
  return lines.join("\n") + "\n";
}

function writeOutput(name, value, file) {
  if (!file) return;
  const delim = `EOF_${Math.random().toString(36).slice(2)}`;
  fs.appendFileSync(file, `${name}<<${delim}\n${value}\n${delim}\n`);
}

async function run(env = process.env) {
  const urls = getInput("urls", env).split(/\r?\n/).map((s) => s.trim()).filter((s) => s && !s.startsWith("#"));
  const failOn = (getInput("fail-on", env) || "fail").toLowerCase();
  const timeoutSeconds = Number(getInput("timeout", env) || 8);
  const ignore = getInput("ignore", env).split(/[\s,]+/).filter(Boolean);
  const errors = [];
  if (!urls.length) errors.push("Input 'urls' is empty. Give one URL per line.");
  if (!["fail", "warn", "none"].includes(failOn)) errors.push(`Input 'fail-on' must be fail, warn or none (got "${failOn}").`);
  if (!(timeoutSeconds > 0 && timeoutSeconds <= 60)) errors.push("Input 'timeout' must be a number of seconds from 1 to 60.");
  if (errors.length) {
    for (const e of errors) console.log(`::error::${e}`);
    return { exitCode: 1, results: [] };
  }

  const results = [];
  for (const u of urls) results.push(await checkUrl(u, { timeoutSeconds, ignore }));

  const totals = { urls: results.length, pass: 0, warn: 0, fail: 0, error: 0 };
  for (const r of results) {
    if (!r.ok) totals.error++; else totals[r.result]++;
    if (!r.ok) console.log(`::error::${r.url}: ${r.error}`);
    else {
      console.log(`${r.url} -> ${r.result.toUpperCase()} (${r.summary.pass} pass, ${r.summary.warn} warn, ${r.summary.fail} fail)`);
      for (const c of r.checks) if (c.status === "fail" || c.status === "warn") console.log(`::${c.status === "fail" ? "error" : "warning"} title=${c.name}::${r.url}: ${c.note}`);
    }
  }
  const worst = totals.fail || totals.error ? "fail" : totals.warn ? "warn" : "pass";
  const json = JSON.stringify({ result: worst, totals, results }, null, 2);
  writeOutput("summary", json, env.GITHUB_OUTPUT);
  writeOutput("result", worst, env.GITHUB_OUTPUT);
  if (env.GITHUB_STEP_SUMMARY) fs.appendFileSync(env.GITHUB_STEP_SUMMARY, markdown(results, failOn));

  let exitCode = 0;
  if (failOn === "fail" && (totals.fail || totals.error)) exitCode = 1;
  if (failOn === "warn" && (totals.fail || totals.warn || totals.error)) exitCode = 1;
  if (exitCode) console.log(`::error::Security header check failed with fail-on=${failOn}.`);
  return { exitCode, results, json };
}

module.exports = { run, getInput, markdown };
