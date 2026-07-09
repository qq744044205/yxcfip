export default {
  async fetch(request, env) {
    if (request.method !== "GET") return new Response("Not Found", { status: 404 });

    const url = new URL(request.url);
    if (!env.ACCESS_TOKEN || url.pathname !== `/${env.ACCESS_TOKEN}/sub`) {
      return new Response("Not Found", { status: 404 });
    }

    const domain = String(env.DOMAIN || "").trim().toLowerCase();
    const uuid = String(env.UUID || "").trim();
    let wsPath = String(env.WS_PATH || "").trim();
    if (!/^[a-z0-9.-]+$/.test(domain) || !isUUID(uuid)) {
      return new Response("Invalid configuration", { status: 500 });
    }
    if (!wsPath.startsWith("/")) wsPath = `/${wsPath}`;

    const configured = String(env.PREFERRED_ADDRESSES || "")
      .split(/[\s,]+/)
      .map(parsePreferredAddress)
      .filter((item) => item.address);

    const sources = configured
      .filter((item) => item.address.startsWith("https://"))
      .map((item) => item.address)
      .slice(0, 5);

    const direct = configured.filter((item) => !item.address.startsWith("https://"));
    const remote = (await Promise.all(sources.map(fetchRemotePreferredAddresses))).flat();

    const items = [{ address: domain, remark: "", skipCloudflareCheck: true }, ...direct, ...remote];
    const addresses = [];
    const seen = new Set();

    for (const item of items) {
      if (!(await isAllowedAddress(item.address, item.skipCloudflareCheck)) || seen.has(item.address)) continue;
      seen.add(item.address);
      addresses.push(item);
      if (addresses.length >= 100) break;
    }

    const links = addresses.map((item, index) => {
      const address = item.address;
      const server = address.includes(":") ? `[${address}]` : address;
      const params = new URLSearchParams({
        encryption: "none",
        security: "tls",
        sni: domain,
        fp: "chrome",
        type: "ws",
        host: domain,
        path: wsPath,
      });
      const baseName = item.remark || `Preferred-${String(index + 1).padStart(2, "0")}`;
      const name = encodeURIComponent(`${baseName}-443-TLS`);
      return `vless://${uuid}@${server}:443?${params}#${name}`;
    });

    return new Response(toBase64(links.join("\n")), {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
      },
    });
  },
};

const CF4 = [
  ["173.245.48.0", 20], ["103.21.244.0", 22], ["103.22.200.0", 22], ["103.31.4.0", 22],
  ["141.101.64.0", 18], ["108.162.192.0", 18], ["190.93.240.0", 20], ["188.114.96.0", 20],
  ["197.234.240.0", 22], ["198.41.128.0", 17], ["162.158.0.0", 15], ["104.16.0.0", 13],
  ["104.24.0.0", 14], ["172.64.0.0", 13], ["131.0.72.0", 22],
];
const CF6 = [
  ["2400:cb00::", 32], ["2606:4700::", 32], ["2803:f800::", 32], ["2405:b500::", 32],
  ["2405:8100::", 32], ["2a06:98c0::", 29], ["2c0f:f248::", 32],
];

async function fetchRemotePreferredAddresses(source) {
  try {
    const url = new URL(source);
    if (url.protocol !== "https:" || url.username || url.password) return [];
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "text/plain,text/csv;q=0.9,*/*;q=0.1" },
      redirect: "follow",
    });
    clearTimeout(timer);
    if (!response.ok || Number(response.headers.get("content-length") || 0) > 262144) return [];
    const text = (await response.text()).slice(0, 262144);
    return parseRemotePreferredText(text).slice(0, 100);
  } catch {
    return [];
  }
}

function parseRemotePreferredText(text) {
  const items = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("//") || line.startsWith(";")) continue;
    const item = parsePreferredAddress(line);
    if (item.address && isSafeAddress(item.address)) items.push(item);
  }
  return items;
}

function parsePreferredAddress(value) {
  const [rawAddress, ...remarkParts] = value.trim().split("#");
  return {
    address: normalizeAddress(rawAddress),
    remark: remarkParts.join("#").trim(),
  };
}

function normalizeAddress(value) {
  let address = value.trim().toLowerCase();
  const v6 = address.match(/^\[([0-9a-f:]+)\](?::\d+)?$/i);
  if (v6) return v6[1];
  if (/^(?:\d{1,3}\.){3}\d{1,3}:\d+$/.test(address)) address = address.replace(/:\d+$/, "");
  return address;
}

function isUUID(v) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v);
}
function isSafeAddress(v) {
  if (v.length > 253 || /[/?#@\s]/.test(v)) return false;
  if (isIPAddress(v)) return true;
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(v);
}
async function isAllowedAddress(v, skipCloudflareCheck = false) {
  if (!isSafeAddress(v)) return false;
  if (skipCloudflareCheck) return true;
  if (isIPAddress(v)) return isCloudflareIP(v);
  const ips = await resolveDomainIPs(v);
  return ips.length > 0 && ips.every(isCloudflareIP);
}
async function resolveDomainIPs(domain) {
  const results = await Promise.all([resolveDNS(domain, "A"), resolveDNS(domain, "AAAA")]);
  return [...new Set(results.flat().filter(isIPAddress))];
}
async function resolveDNS(domain, type) {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 2500);
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/dns-json" },
    });
    clearTimeout(timer);
    if (!response.ok) return [];
    const data = await response.json();
    return Array.isArray(data.Answer)
      ? data.Answer.map((answer) => String(answer.data || "").trim())
      : [];
  } catch {
    return [];
  }
}
function isIPAddress(v) { return isIPv4(v) || isIPv6(v); }
function isIPv4(v) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(v) &&
    v.split(".").every((p) => Number(p) >= 0 && Number(p) <= 255);
}
function isIPv6(v) {
  try { ipv6Big(v); return v.includes(":"); } catch { return false; }
}
function isCloudflareIP(v) {
  if (isIPv4(v)) {
    const ip = ipv4Num(v);
    return CF4.some(([net, p]) => (ip >>> (32 - p)) === (ipv4Num(net) >>> (32 - p)));
  }
  if (isIPv6(v)) {
    const ip = ipv6Big(v);
    return CF6.some(([net, p]) => (ip >> (128n - BigInt(p))) === (ipv6Big(net) >> (128n - BigInt(p))));
  }
  return false;
}
function ipv4Num(v) {
  return v.split(".").reduce((n, p) => ((n << 8) | Number(p)) >>> 0, 0);
}
function ipv6Big(v) {
  if (!/^[0-9a-f:]+$/i.test(v) || (v.match(/::/g) || []).length > 1) throw 0;
  const [a, b = ""] = v.split("::"), left = a ? a.split(":") : [], right = b ? b.split(":") : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (!v.includes("::") && missing !== 0)) throw 0;
  const parts = [...left, ...Array(missing).fill("0"), ...right];
  if (parts.length !== 8 || parts.some((p) => !/^[0-9a-f]{1,4}$/i.test(p))) throw 0;
  return parts.reduce((n, p) => (n << 16n) | BigInt(`0x${p}`), 0n);
}
function toBase64(text) {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
