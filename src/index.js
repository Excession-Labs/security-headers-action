"use strict";
const { run } = require("./main");
run().then(({ exitCode }) => { process.exitCode = exitCode; }, (e) => {
  console.log(`::error::${e?.message || e}`);
  process.exitCode = 1;
});
