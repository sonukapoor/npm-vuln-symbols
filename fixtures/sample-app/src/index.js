// Probe fixture with a deliberately known answer.
//
// lodash 4.17.20 carries two advisories:
//   GHSA-29mw-wpgm-hmr9  ReDoS via toNumber, trim, trimEnd   -> REACHABLE
//   GHSA-35jh-r3h4-6jhm  Command injection via template      -> NOT REACHABLE
//
// This file calls trim and never calls template, so a correct reachability
// result must keep the first and eliminate the second.

const { trim } = require("lodash");

function normaliseQuery(raw) {
  return trim(raw);
}

module.exports = { normaliseQuery };
