// CVSS v3.0/v3.1 base score from a vector string (FIRST specification, section 7).
// OSV publishes CVSS as a vector ("CVSS:3.1/AV:N/..."), not a number.

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
};

function roundup(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvssBaseScore(vector) {
  if (!vector || typeof vector !== "string" || !vector.startsWith("CVSS:3")) return null;
  const m = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    m[k] = v;
  }
  const changed = m.S === "C";
  const prMap = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 };
  const vals = [W.AV[m.AV], W.AC[m.AC], prMap[m.PR], W.UI[m.UI], W.CIA[m.C], W.CIA[m.I], W.CIA[m.A]];
  if (vals.some((x) => x === undefined)) return null;
  const [av, ac, pr, ui, c, i, a] = vals;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const total = changed ? 1.08 * (impact + exploitability) : impact + exploitability;
  return roundup(Math.min(total, 10));
}

export function severityFromScore(score) {
  if (score == null) return null;
  if (score === 0) return "none";
  if (score < 4) return "low";
  if (score < 7) return "medium";
  if (score < 9) return "high";
  return "critical";
}
