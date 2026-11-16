/*
 * phishguard.js - PhishGuard running 100% in the browser.
 *
 * A faithful JavaScript port of features.py + predict.py. It loads the compact
 * Random Forest exported by export_web_model.py (model.json) and evaluates it locally,
 * so no URL ever leaves the visitor's browser.
 *
 * Parity notes (so results match the Python version exactly):
 *   - URLs are split the way Python's urllib.parse.urlparse does it, not with new URL(),
 *     which would rewrite the URL (add a trailing "/", punycode-encode, etc.).
 *   - Lengths count Unicode code points, like Python's len().
 *   - round() uses Python's round-half-to-even on the exact binary value.
 *   - Feature values are cast to float32 before comparing with tree thresholds,
 *     exactly like scikit-learn does.
 */
(function (global) {
  "use strict";

  let M = null;          // loaded model bundle
  let L = null;          // word lists from the model bundle
  let OFFICIAL = null;   // official domain -> brand

  const IP_RE = /^\p{Nd}{1,3}(\.\p{Nd}{1,3}){3}$/u;
  const DIGIT_RE = /[\p{Nd}²³¹⁰⁴-⁹₀-₉]/u;
  const LOOKALIKE = { "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a" };
  const USES_PARAMS = new Set(["", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp",
    "rtsp", "rtsps", "rtspu", "sip", "sips", "mms", "sftp", "tel"]);

  // ---------- small Python-compatible helpers ----------
  const cps = (s) => Array.from(s);                 // code points
  const len = (s) => cps(s).length;                  // Python len()
  const count = (s, sub) => s.split(sub).length - 1; // Python str.count (non-overlapping)

  // Python round(x, nd): round half to even on the exact binary value
  function pyRound(x, nd) {
    if (!isFinite(x)) return x;
    const neg = x < 0, s = Math.abs(x).toFixed(100);
    const dot = s.indexOf(".");
    const keep = s.slice(0, dot + 1 + nd), rest = s.slice(dot + 1 + nd);
    let v = Number(keep);
    const first = rest[0], tail = rest.slice(1);
    const step = Math.pow(10, -nd);
    if (first > "5" || (first === "5" && /[1-9]/.test(tail))) v += step;
    else if (first === "5") {
      const lastDigit = Number(keep.replace(".", "").slice(-1));
      if (lastDigit % 2 === 1) v += step;
    }
    v = Number(v.toFixed(nd));
    return neg ? -v : v;
  }

  // Python str.strip() whitespace
  const pyStrip = (s) => s.replace(/^[\s\u001c-\u001f\u0085]+|[\s\u001c-\u001f\u0085]+$/gu, "");

  function normalize(url) {
    url = pyStrip(String(url));
    if (!/^[a-zA-Z][a-zA-Z0-9+.\-]*:\/\//.test(url)) url = "http://" + url;
    return url;
  }

  // Python urllib.parse.urlparse (only the parts we need)
  function urlparse(url) {
    url = url.replace(/^[\u0000- ]+/, "").replace(/[\t\r\n]/g, "");
    let scheme = "", netloc = "", query = "";
    const i = url.indexOf(":");
    if (i > 0 && /^[A-Za-z]/.test(url[0]) && /^[A-Za-z0-9+.\-]+$/.test(url.slice(0, i))) {
      scheme = url.slice(0, i).toLowerCase();
      url = url.slice(i + 1);
    }
    if (url.slice(0, 2) === "//") {
      let delim = url.length;
      for (const c of "/?#") { const w = url.indexOf(c, 2); if (w >= 0) delim = Math.min(delim, w); }
      netloc = url.slice(2, delim);
      url = url.slice(delim);
    }
    if (url.includes("#")) url = url.slice(0, url.indexOf("#"));
    if (url.includes("?")) { query = url.slice(url.indexOf("?") + 1); url = url.slice(0, url.indexOf("?")); }
    let path = url;
    if (USES_PARAMS.has(scheme) && path.includes(";")) {
      let k;
      if (path.includes("/")) { k = path.indexOf(";", path.lastIndexOf("/")); }
      else k = path.indexOf(";");
      if (k >= 0) path = path.slice(0, k);
    }
    // hostname / port (like SplitResult.hostname / .port)
    const hostinfo = netloc.slice(netloc.lastIndexOf("@") + 1);
    let hostname, port;
    const br = hostinfo.indexOf("[");
    if (br >= 0) {
      const bracketed = hostinfo.slice(br + 1);
      const close = bracketed.indexOf("]");
      hostname = close >= 0 ? bracketed.slice(0, close) : bracketed;
      const after = close >= 0 ? bracketed.slice(close + 1) : "";
      const colon = after.indexOf(":");
      port = colon >= 0 ? after.slice(colon + 1) : "";
    } else {
      const colon = hostinfo.indexOf(":");
      hostname = colon >= 0 ? hostinfo.slice(0, colon) : hostinfo;
      port = colon >= 0 ? hostinfo.slice(colon + 1) : "";
    }
    let hasPort = 0;
    if (port) {
      if (!/^[0-9]+$/.test(port) || Number(port) > 65535) hasPort = 1;   // Python raises ValueError -> 1
      else hasPort = Number(port) ? 1 : 0;
    }
    return { scheme, netloc, path, query, hostname: hostname.toLowerCase(), hasPort };
  }

  function registeredDomain(hostname) {
    const parts = hostname.toLowerCase().replace(/^\.+|\.+$/g, "").split(".");
    if (parts.length <= 2 || IP_RE.test(hostname)) return hostname.toLowerCase();
    const sld = new Set(L.second_level);
    if (sld.has(parts[parts.length - 2]) && len(parts[parts.length - 1]) === 2) return parts.slice(-3).join(".");
    return parts.slice(-2).join(".");
  }

  function entropy(text) {
    const chars = cps(text);
    if (!chars.length) return 0;
    const counts = new Map();
    for (const c of chars) counts.set(c, (counts.get(c) || 0) + 1);
    let total = chars.length, sum = 0;
    for (const n of counts.values()) sum += (n / total) * Math.log2(n / total);
    return -sum;
  }

  function undoLookalikes(text) {
    return cps(text).map((c) => LOOKALIKE[c] || c).join("").split("rn").join("m").split("vv").join("w");
  }

  function brandMisuse(urlLower, reg) {
    const cands = [urlLower, undoLookalikes(urlLower)];
    for (const [brand, real] of Object.entries(L.brands)) {
      if (cands.some((c) => c.includes(brand)) && !real.includes(reg)) return 1;
    }
    return 0;
  }

  // Same order as FEATURE_NAMES in features.py
  function extractFeatures(rawUrl) {
    const url = normalize(rawUrl);
    const p = urlparse(url);
    const hostname = p.hostname, path = p.path, query = p.query, urlLower = url.toLowerCase();
    const reg = registeredDomain(hostname);
    const tld = hostname.includes(".") ? hostname.slice(hostname.lastIndexOf(".") + 1) : "";
    const hasIp = IP_RE.test(hostname) ? 1 : 0;
    const hc = cps(hostname);
    const subPart = hasIp ? "" : hc.slice(0, Math.max(0, hc.length - len(reg))).join("").replace(/^\.+|\.+$/g, "");
    const subdomains = subPart.split(".").filter((s) => s && s !== "www");
    const uc = cps(url);
    const digits = uc.filter((c) => DIGIT_RE.test(c)).length;
    const tokens = hostname ? hostname.split(/[.\-]/) : [""];
    const tlds = new Set(L.suspicious_tlds), shorteners = new Set(L.url_shorteners);

    return [
      uc.length,
      hc.length,
      len(path),
      count(url, "."),
      count(hostname, "-"),
      count(url, "@"),
      digits,
      pyRound(digits / Math.max(uc.length, 1), 4),
      Array.from("%=?&~_+!*").reduce((s, c) => s + count(url, c), 0),
      query.split("&").filter((x) => x).length,
      subdomains.length,
      hasIp,
      p.scheme === "https" ? 1 : 0,
      p.hasPort,
      tlds.has(tld) ? 1 : 0,
      shorteners.has(reg) ? 1 : 0,
      hostname.includes("xn--") ? 1 : 0,
      uc.slice(8).join("").includes("//") ? 1 : 0,
      L.suspicious_words.filter((w) => urlLower.includes(w)).length,
      brandMisuse(urlLower, reg),
      pyRound(entropy(hostname), 4),
      Math.max(...tokens.map(len)),
    ];
  }

  // Random Forest: average of the leaf probabilities of every tree
  function predictProba(x) {
    const xf = x.map(Math.fround);   // scikit-learn compares in float32
    let sum = 0;
    for (const t of M.trees) {
      let n = 0;
      while (t.f[n] !== -1) n = xf[t.f[n]] <= t.t[n] ? t.l[n] : t.r[n];
      sum += t.p[n];
    }
    return sum / M.trees.length;
  }

  function explain(url, f) {
    const host = urlparse(normalize(url)).hostname;
    const reg = registeredDomain(host);
    const r = [];
    if (f.has_ip) r.push(["high", "Uses an IP address instead of a domain name"]);
    if (f.brand_misuse) {
      const look = undoLookalikes(host) !== host && !Object.keys(L.brands).some((b) => host.includes(b));
      r.push(["high", look ? `Imitates a brand name with look-alike characters (real domain: '${reg}')`
                           : `Mentions a well-known brand, but the real domain is '${reg}'`]);
    }
    if (f.num_at) r.push(["high", "Contains '@' - browsers ignore everything before it"]);
    if (f.has_punycode) r.push(["high", "Uses punycode (xn--) - may imitate letters from another alphabet"]);
    if (f.double_slash_redirect) r.push(["medium", "Contains '//' inside the path - possible hidden redirect"]);
    if (f.suspicious_tld) r.push(["medium", `Uses a top-level domain often abused by scammers (.${host.slice(host.lastIndexOf(".") + 1)})`]);
    if (f.is_shortener) r.push(["medium", "Shortened link - the real destination is hidden"]);
    if (f.suspicious_word_count >= 2) r.push(["medium", `Contains ${f.suspicious_word_count} pressure words (login, verify, urgent ...)`]);
    else if (f.suspicious_word_count === 1) r.push(["low", "Contains a sensitive word (login, verify, account ...)"]);
    if (f.num_subdomains >= 3) r.push(["medium", `Has ${f.num_subdomains} subdomains - used to hide the real domain`]);
    if (f.num_hyphens_host >= 2) r.push(["low", "Many hyphens in the domain name"]);
    if (f.has_port) r.push(["low", "Uses a non-standard port number"]);
    if (!f.uses_https) r.push(["low", "Not using HTTPS (no encryption)"]);
    if (f.url_length > 90) r.push(["low", `Very long URL (${f.url_length} characters)`]);
    const name = reg.split(".")[0];
    const vowels = cps(name).filter((c) => "aeiou".includes(c)).length;
    if (!f.has_ip && len(name) >= 10 && !name.includes("-") && entropy(name) > 3.2 && vowels / len(name) < 0.3)
      r.push(["low", `Domain name '${name}' looks randomly generated`]);
    return r.map(([level, text]) => ({ level, text }));
  }

  function analyze(url) {
    if (!M) throw new Error("Model not loaded yet");
    const x = extractFeatures(url);
    const f = Object.fromEntries(M.feature_names.map((n, i) => [n, x[i]]));
    let risk = pyRound(predictProba(x) * 100, 1);
    let reasons = explain(url, f);

    const host = urlparse(normalize(url)).hostname;
    const brand = OFFICIAL[registeredDomain(host)];
    if (brand) {
      risk = Math.min(risk, 5.0);
      const name = brand.length <= 5 ? brand.toUpperCase() : brand[0].toUpperCase() + brand.slice(1);
      reasons = [{ level: "info", text: `Verified official domain of ${name} (allowlist)` }]
        .concat(reasons.filter((r) => r.level === "low"));
    }
    const verdict = risk >= 70 ? "PHISHING" : risk >= 40 ? "SUSPICIOUS" : "SAFE";
    return { url: normalize(url), verdict, risk, reasons, features: f };
  }

  async function load(modelUrl) {
    const res = await fetch(modelUrl || "model.json");
    if (!res.ok) throw new Error("Could not load the model (" + res.status + ")");
    M = await res.json();
    L = M.lists;
    OFFICIAL = {};
    for (const [brand, domains] of Object.entries(L.brands)) for (const d of domains) OFFICIAL[d] = brand;
    return M;
  }

  global.PhishGuard = { load, analyze, extractFeatures, predictProba, get model() { return M; } };
})(window);
