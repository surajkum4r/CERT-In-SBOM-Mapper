// Loose version comparison and fix-version selection.

function vkey(v) {
  const s = String(v).trim().replace(/^[vV]/, "");
  const dash = s.indexOf("-");
  const main = dash >= 0 ? s.slice(0, dash) : s;
  const pre = dash >= 0 ? s.slice(dash + 1) : "";
  const nums = main.split(/[.+_]/).map((part) => {
    const m = part.match(/^(\d+)(.*)$/);
    return m ? [Number(m[1]), m[2]] : [-1, part];
  });
  return { nums, pre };
}

// true when a < b
export function versionLt(a, b) {
  if (a == null || b == null) return false;
  const ka = vkey(a);
  const kb = vkey(b);
  const n = Math.max(ka.nums.length, kb.nums.length);
  for (let i = 0; i < n; i++) {
    const [an, as] = ka.nums[i] || [0, ""];
    const [bn, bs] = kb.nums[i] || [0, ""];
    if (an !== bn) return an < bn;
    if (as !== bs) return as < bs;
  }
  // a pre-release sorts before the release
  if (ka.pre && !kb.pre) return true;
  if (!ka.pre && kb.pre) return false;
  return ka.pre < kb.pre;
}

export function sortVersions(versions) {
  return Array.from(new Set(versions)).sort((a, b) => (versionLt(a, b) ? -1 : versionLt(b, a) ? 1 : 0));
}

// Highest fix on the same release line (major.minor, then major); else the lowest newer release.
// Advisories list fixes for every maintained branch, so picking the first or the maximum
// would suggest a downgrade or an unnecessary major upgrade (e.g. Django 4.2.7 -> 6.x).
export function bestFix(current, fixed) {
  const newer = sortVersions((fixed || []).filter((f) => !current || versionLt(current, f)));
  const pool = newer.length ? newer : sortVersions(fixed || []);
  if (!pool.length) return null;
  if (!current) return pool[pool.length - 1];
  const parts = String(current).replace(/^[vV]/, "").split(".");
  for (const depth of [2, 1]) {
    const prefix = parts.slice(0, depth).join(".") + ".";
    const sameLine = pool.filter((f) => String(f).replace(/^[vV]/, "").startsWith(prefix));
    if (sameLine.length) return sameLine[sameLine.length - 1];
  }
  return pool[0];
}
