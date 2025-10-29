/* Clean implementation: no WARP, no extra toggles. 
   - Loads templates list from templates/index.json
   - Fetches selected template file
   - Parses input links (vless/vmess/ss/trojan/hysteria2)
   - Generates YAML 'proxies:' entries and injects/replaces in template
   - Provides copy & download helpers
*/

// ---------- Helpers: UI ----------
const $ = (sel) => document.querySelector(sel);

async function loadTemplatesList() {
  const select = $('#templateSelect');
  select.innerHTML = '';
  try {
    const resp = await fetch('./templates/index.json', { cache: 'no-store' });
    if (!resp.ok) throw new Error('templates/index.json not found');
    const list = await resp.json();
    if (!Array.isArray(list) || list.length === 0) throw new Error('Пустой список шаблонов');
    list.forEach(item => {
      const opt = document.createElement('option');
      opt.value = item.file;
      opt.textContent = item.name || item.file;
      select.appendChild(opt);
    });
  } catch (e) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Ошибка: ' + e.message + ' — можно выбрать локальные файлы шаблонов';
    $('#templateSelect').appendChild(opt);
    enableLocalPickerUI();
  }
}

async function getSelectedTemplateText() {
  const value = $('#templateSelect').value;
  if (!value) throw new Error('Не выбран шаблон');
  if (value.startsWith('local:')) {
    const label = value.slice('local:'.length);
    const f = LOCAL_TEMPLATES.get(label);
    if (!f) throw new Error('Локальный файл не найден в списке');
    return await readFileAsText(f);
  }
  const resp = await fetch('./templates/' + value + '?t=' + Date.now());
  if (!resp.ok) throw new Error('Не удалось загрузить шаблон: ' + value);
  return await resp.text();
}

function showError(message) {
  alert(message);
}

// ---------- Convert button ----------
$('#convertBtn')?.addEventListener('click', async () => {
  try {
    const input = $('#yamlInput').value.trim();
    if (!input) {
      showError('Введите ссылку(и) для конвертации');
      return;
    }
    const lines = input.split('\n').map(s => s.trim()).filter(Boolean);
    const proxies = [];
    for (const line of lines) {
      if (line.startsWith('vless://')) proxies.push(parseVlessUri(line));
      else if (line.startsWith('vmess://')) proxies.push(parseVmessUri(line));
      else if (line.startsWith('ss://')) proxies.push(parseShadowsocksUri(line));
      else if (line.startsWith('trojan://')) proxies.push(parseTrojanUri(line));
      else if (line.startsWith('hysteria2://') || line.startsWith('hy2://')) proxies.push(parseHysteria2Uri(line));
      else throw new Error('Неподдерживаемая ссылка: ' + line);
    }

    // Build 'proxies:' YAML block only
    const proxiesYaml = buildProxiesYaml(proxies);

    // Load template and inject/replace proxies
    const template = await getSelectedTemplateText();
    const merged = mergeTemplateWithProxies(template, proxiesYaml);

    $('#yamlOutput').value = merged;
    setupDownloadAndCopy();
  } catch (e) {
    showError(e.message || String(e));
  }
});

$('#copyBtn')?.addEventListener('click', copyToClipboard);
$('#downloadBtn')?.addEventListener('click', downloadConfig);
$('#reloadTemplates')?.addEventListener('click', loadTemplatesList);

document.addEventListener('DOMContentLoaded', loadTemplatesList);

// ---------- Local file fallback (for file://) ----------
const templateFilesInput = $('#templateFiles');
const pickLocalBtn = $('#pickLocalTemplates');
let LOCAL_TEMPLATES = new Map(); // key: label, value: File

function enableLocalPickerUI() {
  pickLocalBtn.classList.remove('hidden');
  pickLocalBtn.addEventListener('click', () => templateFilesInput.click());
  templateFilesInput.addEventListener('change', handleLocalTemplatesChosen, { once: false });
}

async function handleLocalTemplatesChosen(ev) {
  LOCAL_TEMPLATES.clear();
  const files = Array.from(ev.target.files || [])
    .filter(f => /\.(ya?ml)$/i.test(f.name));
  const select = $('#templateSelect');
  select.innerHTML = '';
  for (const f of files) {
    const label = f.name;
    LOCAL_TEMPLATES.set(label, f);
    const opt = document.createElement('option');
    opt.value = 'local:' + label;
    opt.textContent = label + ' (локальный)';
    select.appendChild(opt);
  }
  if (files.length === 0) {
    const opt = document.createElement('option');
    opt.value = ''; opt.textContent = 'Не выбраны локальные шаблоны';
    select.appendChild(opt);
  }
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error);
    reader.readAsText(file);
  });
}


// ---------- Merge logic ----------
function mergeTemplateWithProxies(templateText, proxiesYaml) {
  // 1) If template already contains 'proxies:' -> replace its block
  // The block ends before next top-level section: proxy-groups:, proxy-providers:, rule-providers:, rules:, sniffer:, dns:, tun:
  const sections = ['proxy-providers:', 'proxy-groups:', 'rule-providers:', 'rules:', 'sniffer:', 'dns:', 'tun:'];
  const proxiesIdx = templateText.indexOf('proxies:');
  if (proxiesIdx !== -1) {
    let end = templateText.length;
    for (const s of sections) {
      const i = templateText.indexOf(s, proxiesIdx + 1);
      if (i !== -1 && i < end) end = i;
    }
    const before = templateText.slice(0, proxiesIdx).trimEnd();
    const after = templateText.slice(end).trimStart();
    return [before, proxiesYaml, after].filter(Boolean).join('\n\n') + '\n';
  }

  // 2) If there's no proxies:, try to insert before proxy-groups: (or append to the end)
  let insertAt = -1;
  for (const s of ['proxy-groups:', 'proxy-providers:', 'rule-providers:', 'rules:', 'sniffer:', 'dns:', 'tun:']) {
    const i = templateText.indexOf(s);
    if (i !== -1) { insertAt = i; break; }
  }

  if (insertAt !== -1) {
    const before = templateText.slice(0, insertAt).trimEnd();
    const after = templateText.slice(insertAt).trimStart();
    return [before, proxiesYaml, after].filter(Boolean).join('\n\n') + '\n';
  }

  // 3) Fallback: append
  return (templateText.trimEnd() + '\n\n' + proxiesYaml + '\n');
}

// ---------- YAML builders (only 'proxies:' block) ----------
function buildProxiesYaml(proxies) {
  let yaml = 'proxies:';
  for (const p of proxies) {
    yaml += '\n' + buildSingleProxyYaml(p);
  }
  return yaml;
}

function buildSingleProxyYaml(p) {
  switch (p.type) {
    case 'vless': return asBlock(`- name: "${safe(p.name)}"
  type: vless
  server: '${p.server}'
  port: ${p.port}
  uuid: '${p.uuid}'` + 
  (p.tls ? `
  tls: true` : '') + 
  (p.sni ? `
  servername: '${p.sni}'` : '') + 
  (p.flow ? `
  flow: '${p.flow}'` : '') + 
  (p['skip-cert-verify'] !== undefined ? `
  skip-cert-verify: ${p['skip-cert-verify']}` : '') + 
  (p['client-fingerprint'] ? `
  client-fingerprint: '${p['client-fingerprint']}'` : '') + 
  (p.alpn?.length ? `
  alpn:${p.alpn.map(a => `\n    - '${a}'`).join('')}` : '') + 
  (p.network ? `
  network: '${p.network}'` : '') + 
  (p['reality-opts'] && (p['reality-opts']['public-key'] || p['reality-opts']['short-id']) ? `
  reality-opts:${p['reality-opts']['public-key'] ? `
    public-key: '${p['reality-opts']['public-key']}'` : ''}${p['reality-opts']['short-id'] ? `
    short-id: '${p['reality-opts']['short-id']}'` : ''}` : '') + 
  (p.network === 'ws' && p['ws-opts'] ? buildWsOpts(p['ws-opts']) : '') + 
  (p.network === 'grpc' && p['grpc-opts']?.['grpc-service-name'] ? `
  grpc-opts:
    grpc-service-name: '${p['grpc-opts']['grpc-service-name']}'` : ''));
    case 'vmess': return asBlock(`- name: "${safe(p.name)}"
  type: vmess
  server: '${p.server}'
  port: ${p.port}
  uuid: '${p.uuid}'
  udp: true
  alterId: ${p.alterId || 0}
  cipher: '${p.cipher || "auto"}'` + 
  (p.tls ? `
  tls: true` : '') +
  (p.servername ? `
  servername: '${p.servername}'` : '') +
  (p["skip-cert-verify"] !== undefined ? `
  skip-cert-verify: ${p["skip-cert-verify"]}` : '') +
  (p.network ? `
  network: '${p.network}'` : '') +
  (p.network === 'ws' && p['ws-opts'] ? buildWsOpts(p['ws-opts']) : '') +
  (p.network === 'grpc' && p['grpc-opts']?.['grpc-service-name'] ? `
  grpc-opts:
    grpc-service-name: '${p['grpc-opts']['grpc-service-name']}'` : ''));
    case 'ss': return asBlock(`- name: "${safe(p.name)}"
  type: ss
  server: '${p.server}'
  port: ${p.port}
  cipher: '${p.cipher}'
  password: '${p.password}'
  udp: true` + (p.plugin ? `
  plugin: '${p.plugin}'` : '') + buildPluginOpts(p['plugin-opts']));
    case 'trojan': return asBlock(`- name: "${safe(p.name)}"
  type: trojan
  server: '${p.server}'
  port: ${p.port}
  password: '${p.password}'
  udp: true
  tls: true` + 
  (p.sni ? `
  servername: '${p.sni}'` : '') + 
  (p["skip-cert-verify"] !== undefined ? `
  skip-cert-verify: ${p["skip-cert-verify"]}` : '') + 
  (p["client-fingerprint"] ? `
  client-fingerprint: '${p["client-fingerprint"]}'` : '') + 
  (p.alpn?.length ? `
  alpn:${p.alpn.map(a => `\n    - '${a}'`).join('')}` : '') + 
  (p.network && p.network !== 'tcp' ? `
  network: '${p.network}'` : '') + 
  (p.network === 'ws' && p['ws-opts'] ? buildWsOpts(p['ws-opts']) : '') + 
  (p.network === 'grpc' && p['grpc-opts']?.['grpc-service-name'] ? `
  grpc-opts:
    grpc-service-name: '${p['grpc-opts']['grpc-service-name']}'` : ''));
    case 'hysteria2': return asBlock(`- name: "${safe(p.name)}"
  type: hysteria2
  server: '${p.server}'
  port: ${p.port}
  password: '${p.password}'` + 
  (p.sni ? `
  sni: '${p.sni}'` : '') + 
  (p.obfs ? `
  obfs: '${p.obfs}'` : '') + 
  (p["obfs-password"] ? `
  obfs-password: '${p["obfs-password"]}'` : '') + `
  skip-cert-verify: ${p["skip-cert-verify"] || false}
  tfo: ${p.tfo || false}` + 
  (p.fingerprint ? `
  fingerprint: '${p.fingerprint}'` : ''));
    default: throw new Error('Unknown proxy type: ' + p.type);
  }
}

function buildWsOpts(ws) {
  let out = '\n  ws-opts:';
  if (ws.path) out += `\n    path: '${ws.path}'`;
  if (ws.headers && Object.keys(ws.headers).length > 0) {
    out += '\n    headers:';
    for (const [k, v] of Object.entries(ws.headers)) out += `\n      ${k}: '${v}'`;
  }
  if (ws["v2ray-http-upgrade"]) out += '\n    v2ray-http-upgrade: true';
  if (ws["v2ray-http-upgrade-fast-open"]) out += '\n    v2ray-http-upgrade-fast-open: true';
  return out;
}

function buildPluginOpts(opts) {
  if (!opts) return '';
  let out = '\n  plugin-opts:';
  for (const [k, v] of Object.entries(opts)) {
    if (typeof v === 'boolean') out += `\n    ${k}: ${v}`;
    else out += `\n    ${k}: '${v}'`;
  }
  return out;
}

function asBlock(s) { return s; }
function safe(s) { return String(s || '').replace(/'/g, "''"); }

// ---------- Parsers (ported & lightly cleaned from your previous script) ----------
function parseHysteria2Uri(line) {
  const match = line.match(/(?:hysteria2|hy2):\/\/([^@]+)@([^:]+):(\d+)(?:\/?\?([^#]*))?(?:#(.*))?/);
  if (!match) throw new Error('Invalid Hysteria2 URI format');
  const [_, password, server, portStr, paramsStr = "", name = ""] = match;
  const port = parseInt(portStr, 10);
  const decodedName = decodeURIComponent(name).trim() || `Hysteria2 ${server}:${port}`;
  const proxy = { type: "hysteria2", name: decodedName, server, port, password: decodeURIComponent(password),
    sni: undefined, obfs: undefined, "obfs-password": undefined, "skip-cert-verify": false, fingerprint: undefined, tfo: false };
  const params = new URLSearchParams(paramsStr || "");
  if (params.has('obfs')) {
    proxy.obfs = params.get('obfs');
    if (proxy.obfs === 'none') proxy.obfs = undefined;
    else if (params.has('obfs-password')) proxy["obfs-password"] = params.get('obfs-password');
  }
  proxy.sni = params.get('sni') || params.get('peer');
  proxy["skip-cert-verify"] = params.has('insecure') && /(TRUE)|1/i.test(params.get('insecure'));
  proxy.fingerprint = params.get('fp') || params.get('fingerprint') || params.get('pinSHA256');
  proxy.tfo = params.has('tfo') && /(TRUE)|1/i.test(params.get('tfo'));
  return proxy;
}

function parseVlessUri(line) {
  line = line.split('vless://')[1];
  let isShadowrocket;
  let parsed = /^(.*?)@(.*?):(\d+)\/?(\?(.*?))?(?:#(.*?))?$/.exec(line);
  if (!parsed) {
    let [_, base64, other] = /^(.*?)(\?.*?$)/.exec(line);
    line = `${atob(base64)}${other}`;
    parsed = /^(.*?)@(.*?):(\d+)\/?(\?(.*?))?(?:#(.*?))?$/.exec(line);
    isShadowrocket = true;
  }
  let [__, uuid, server, portStr, ___, addons = "", name] = parsed;
  if (isShadowrocket) uuid = uuid.replace(/^.*?:/g, "");
  const port = parseInt(portStr, 10);
  uuid = decodeURIComponent(uuid);
  name = decodeURIComponent(name || '').trim();
  const proxy = { type: "vless", name: name || `VLESS ${server}:${port}`, server, port, uuid, tls: false, network: "tcp",
    alpn: [], "ws-opts": {"v2ray-http-upgrade": false, "v2ray-http-upgrade-fast-open": false}, "http-opts": {},
    "grpc-opts": {}, "reality-opts": {}, "client-fingerprint": undefined, sni: undefined };
  const params = {};
  if (addons) for (const addon of addons.split('&')) {
    const [key, valueRaw] = addon.split('=');
    const value = decodeURIComponent(valueRaw || ''); params[key] = value;
  }
  proxy.tls = (params.security && params.security !== 'none') || undefined;
  if (isShadowrocket && /TRUE|1/i.test(params.tls)) { proxy.tls = true; params.security = params.security || "reality"; }
  proxy.sni = params.sni || params.peer;
  proxy.flow = params.flow ? 'xtls-rprx-vision' : undefined;
  proxy['skip-cert-verify'] = /(TRUE)|1/i.test(params.allowInsecure || '');
  proxy['client-fingerprint'] = params.fp;
  if (params.alpn) proxy.alpn = params.alpn.replace(/%2F/g, '/').split(',');
  if (params.security === "reality") {
    if (params.pbk) proxy['reality-opts']['public-key'] = params.pbk;
    if (params.sid) proxy['reality-opts']['short-id'] = params.sid;
  }
  if (params.type === 'httpupgrade') {
    proxy.network = 'ws';
    proxy['ws-opts']['v2ray-http-upgrade'] = true;
    proxy['ws-opts']['v2ray-http-upgrade-fast-open'] = true;
  } else {
    proxy.network = params.type || 'tcp';
    if (!['tcp','ws','http','grpc','h2'].includes(proxy.network)) proxy.network = 'tcp';
  }
  switch (proxy.network) {
    case 'ws':
      if (params.path) proxy['ws-opts'].path = decodeURIComponent(params.path);
      if (params.host || params.obfsParam) {
        const host = params.host || params.obfsParam;
        try { const parsedHeaders = JSON.parse(host); if (Object.keys(parsedHeaders).length) proxy['ws-opts'].headers = parsedHeaders; }
        catch { if (host) { proxy['ws-opts'].headers = proxy['ws-opts'].headers || {}; proxy['ws-opts'].headers.Host = host; } }
      }
      if (params.eh && params.eh.includes(':')) {
        const [headerName, headerValue] = params.eh.split(':').map(s => s.trim());
        if (headerName && headerValue) { proxy['ws-opts'].headers = proxy['ws-opts'].headers || {}; proxy['ws-opts'].headers[headerName] = headerValue; }
      }
      break;
    case 'grpc':
      proxy['grpc-opts'] = {};
      if (params.serviceName) proxy['grpc-opts']['grpc-service-name'] = decodeURIComponent(params.serviceName);
      break;
    case 'http':
      proxy['http-opts'] = { headers: {} };
      if (params.path) proxy['http-opts'].path = decodeURIComponent(params.path);
      if (params.host || params.obfsParam) {
        const host = params.host || params.obfsParam;
        try { proxy['http-opts'].headers = JSON.parse(host); }
        catch { if (host) { proxy['http-opts'].headers.Host = host; } }
      }
      break;
  }
  return proxy;
}

function parseVmessUri(line) {
  line = line.split('vmess://')[1];
  let content = atob(line);
  let params;
  try { params = JSON.parse(content); }
  catch {
    const match = /(^[^?]+?)\/?\?(.*)$/.exec(line);
    if (match) {
      let [_, base64Line, qs] = match;
      content = atob(base64Line); params = {};
      for (const addon of qs.split('&')) {
        const [key, valueRaw] = addon.split('=');
        params[key] = decodeURIComponent(valueRaw);
      }
      const contentMatch = /(^[^:]+?):([^:]+?)@(.*):(\d+)$/.exec(content);
      if (contentMatch) {
        let [__, cipher, uuid, server, port] = contentMatch;
        params.scy = cipher; params.id = uuid; params.port = port; params.add = server;
      }
    } else throw new Error('Неверный формат VMess ссылки');
  }
  const server = params.add || params.address || params.host;
  const port = parseInt(params.port, 10);
  const name = params.ps || params.remarks || params.remark || `VMess ${server}:${port}`;
  const proxy = { type: "vmess", name, server, port, uuid: params.id, alterId: parseInt(params.aid || params.alterId || 0, 10),
    cipher: params.scy || "auto", tls: params.tls === "tls" || params.tls === "1" || params.tls === 1,
    "skip-cert-verify": params.allowInsecure === "1" || params.allowInsecure === "true",
    network: params.net || "tcp", "ws-opts": {"v2ray-http-upgrade": false, "v2ray-http-upgrade-fast-open": false},
    "http-opts": {}, "grpc-opts": {} };
  if (params.sni) proxy.servername = params.sni;
  if (params.net === "httpupgrade") {
    proxy.network = "ws";
    proxy["ws-opts"]["v2ray-http-upgrade"] = true;
    proxy["ws-opts"]["v2ray-http-upgrade-fast-open"] = true;
  } else if (proxy.network === "ws") {
    proxy["ws-opts"].path = params.path || "/";
    proxy["ws-opts"].headers = {};
    if (params.host) {
      try { proxy["ws-opts"].headers = JSON.parse(params.host); }
      catch { proxy["ws-opts"].headers.Host = params.host; }
    }
  } else if (proxy.network === "http") {
    proxy["http-opts"] = { path: params.path ? [params.path] : ["/"], headers: { Host: params.host ? [params.host] : [] } };
  } else if (proxy.network === "grpc") {
    proxy["grpc-opts"] = { "grpc-service-name": params.path || "" };
  }
  return proxy;
}

function parseShadowsocksUri(line) {
  line = line.split('ss://')[1];
  let [userinfo, serverInfo] = line.split('@');
  let [server, port] = (serverInfo || '').split(':');
  port = parseInt(port, 10);
  try { userinfo = atob(userinfo); } catch {}
  let [method, password] = (userinfo || '').split(':');
  const name = decodeURIComponent((line.split('#')[1] || `Shadowsocks ${server}:${port}`));
  const proxy = { type: "ss", name, server, port, cipher: method, password };
  if (line.includes('?plugin=')) {
    const pluginStr = decodeURIComponent(line.split('?plugin=')[1].split('#')[0]);
    const pluginParts = pluginStr.split(';');
    if (pluginParts[0].includes('obfs')) {
      proxy.plugin = "obfs";
      proxy["plugin-opts"] = { mode: pluginParts.find(p => p.startsWith('obfs='))?.split('=')[1] || "http",
                               host: pluginParts.find(p => p.startsWith('obfs-host='))?.split('=')[1] || "" };
    } else if (pluginParts[0].includes('v2ray-plugin')) {
      proxy.plugin = "v2ray-plugin";
      proxy["plugin-opts"] = { mode: "websocket",
                               host: pluginParts.find(p => p.startsWith('host='))?.split('=')[1] || "",
                               path: pluginParts.find(p => p.startsWith('path='))?.split('=')[1] || "/",
                               tls: pluginParts.includes('tls') };
    }
  }
  return proxy;
}

function parseTrojanUri(line) {
  line = line.split('trojan://')[1];
  let [__, password, server, ___, port, ____, addons = "", name] =
    /^(.*?)@(.*?)(:(\d+))?\/?(\?(.*?))?(?:#(.*?))?$/.exec(line) || [];
  let portNum = parseInt(`${port}`, 10); if (isNaN(portNum)) portNum = 443;
  password = decodeURIComponent(password);
  const decodedName = decodeURIComponent(name || '').trim();
  const proxy = { type: "trojan", name: decodedName || `Trojan ${server}:${portNum}`, server, port: portNum, password,
    "skip-cert-verify": false, sni: "", alpn: [], network: "tcp", "grpc-opts": {}, "ws-opts": { "v2ray-http-upgrade": false, "v2ray-http-upgrade-fast-open": false } };
  if (addons) {
    const paramsStr = addons.split('#')[0];
    for (const param of paramsStr.split('&')) {
      const [key, value] = param.split('=');
      const v = decodeURIComponent(value || '');
      switch (key) {
        case 'allowInsecure': case 'allow_insecure': proxy["skip-cert-verify"] = v === '1' || v == 'true'; break;
        case 'sni': case 'peer': proxy.sni = v; break;
        case 'type': proxy.network = (v === 'httpupgrade') ? 'ws' : v; break;
        case 'host': if (proxy.network === 'ws') { proxy["ws-opts"].headers = proxy["ws-opts"].headers || {}; proxy["ws-opts"].headers.Host = v; } break;
        case 'path': if (proxy.network === 'ws') { proxy["ws-opts"].path = v; } break;
        case 'alpn': proxy.alpn = v.split(','); break;
        case 'fp': case 'fingerprint': proxy["client-fingerprint"] = v; break;
      }
    }
  }
  return proxy;
}

// ---------- Copy & Download ----------
function setupDownloadAndCopy() {
  const downloadBtn = $('#downloadBtn');
  downloadBtn.classList.remove('hidden');
}

function downloadConfig() {
  const config = $('#yamlOutput').value;
  const blob = new Blob([config], { type: 'text/yaml; charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'mihomo-config.yaml';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function copyToClipboard() {
  const text = $('#yamlOutput').value;
  const ta = document.createElement('textarea'); ta.value = text;
  document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
  const btn = $('#copyBtn'); const t = btn.textContent; btn.textContent = 'Скопировано!'; setTimeout(()=>btn.textContent=t, 1500);
}
