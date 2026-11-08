'use strict';

const TOKEN = document.querySelector('meta[name="token"]').content;
const APP_VERSION = '3.0';
const Q = (s) => document.querySelector(s);
const QA = (s) => Array.from(document.querySelectorAll(s));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fmtSize = (n) => n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB'
  : (n / 1048576).toFixed(2) + ' MB';
const fmtNum = (n) => (n || 0).toLocaleString('zh-CN');
const stem = (name) => name.replace(/\.[^.]+$/, '');
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const PAGES = {
  icon: ['图标提取', '从 EXE / DLL 中拆出多尺寸图标，导出 ICO 与透明 PNG'],
  upx: ['UPX 加壳', '内置 UPX 引擎，压缩、脱壳、完整性校验一站完成'],
  vm: ['VM 虚拟壳', '把程序加密封装进随机生成的虚拟机外壳，每次构建都不一样'],
  apk: ['APK 加固', '抽出 dex 加密后由壳加载，产出可直接安装的签名包'],
  about: ['关于', '本地运行，不上传任何文件'],
};

const S = { page: 'icon', files: { icon: null, upx: null, vm: null, apk: null }, busy: false, outdir: '' };

/* ------------------------------ 通用请求 ------------------------------ */
async function apiGet(path) {
  const url = path + (path.includes('?') ? '&' : '?') + 't=' + encodeURIComponent(TOKEN);
  const r = await fetch(url, { headers: { 'X-Token': TOKEN } });
  const j = await r.json().catch(() => ({ error: '响应解析失败' }));
  if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
  return j;
}
async function apiPost(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Token': TOKEN },
    body: JSON.stringify(body || {}),
  });
  const j = await r.json().catch(() => ({ error: '响应解析失败' }));
  if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status);
  return j;
}
function upload(file, onPct) {
  return new Promise((res, rej) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/upload');
    xhr.setRequestHeader('X-Token', TOKEN);
    xhr.setRequestHeader('X-Filename', encodeURIComponent(file.name));
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.upload.onprogress = (e) => { if (e.lengthComputable) onPct(e.loaded / e.total); };
    xhr.onload = () => {
      try {
        const j = JSON.parse(xhr.responseText);
        if (xhr.status === 200) res(j); else rej(new Error(j.error || xhr.status));
      } catch (e) { rej(new Error('上传响应异常')); }
    };
    xhr.onerror = () => rej(new Error('网络错误'));
    xhr.send(file);
  });
}

/* ------------------------------ 日志 ------------------------------ */
const LOG_BOX = () => Q('#log');
function log(text, tag) {
  const box = LOG_BOX();
  const line = document.createElement('span');
  line.className = 'l-' + (tag || 'INFO');
  line.textContent = text + '\n';
  box.appendChild(line);
  while (box.childElementCount > 1200) box.removeChild(box.firstChild);
  box.scrollTop = box.scrollHeight;
}
function stamp(text, tag) {
  const d = new Date();
  const t = [d.getHours(), d.getMinutes(), d.getSeconds()].map((x) => String(x).padStart(2, '0')).join(':');
  log(`[${t}] ${text}`, tag);
}
function focusResult(el) {
  if (!el) return;
  requestAnimationFrame(() => el.scrollIntoView({ block: 'nearest', behavior: 'smooth' }));
}

/* ------------------------------ 任务 ------------------------------ */
async function runJob(url, body, onResult) {
  const t0 = Date.now();
  setBusy(true);
  try {
    const j = await apiPost(url, body);
    let since = 0;
    for (;;) {
      const r = await apiGet(`/api/job?id=${j.job}&since=${since}`);
      (r.logs || []).forEach(([tag, text]) => log(text, tag));
      since = r.next;
      if (r.state !== 'running') {
        if (r.state === 'error') { stamp('失败：' + r.error, 'ERR'); throw new Error(r.error); }
        stamp(`完成，用时 ${((Date.now() - t0) / 1000).toFixed(1)} 秒`, 'OK');
        if (onResult) onResult(r.result);
        return r.result;
      }
      await sleep(320);
    }
  } finally {
    setBusy(false);
  }
}
function setBusy(on) {
  S.busy = on;
  QA('.btn').forEach((b) => { b.disabled = on; });
  document.body.style.cursor = on ? 'progress' : '';
}

/* ------------------------------ 页面切换 ------------------------------ */
function go(page) {
  S.page = page;
  QA('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
  QA('.page').forEach((p) => p.classList.toggle('active', p.id === 'page-' + page));
  const [t, s] = PAGES[page];
  Q('#pageTitle').textContent = t;
  Q('#pageSub').textContent = s;
  refreshBadge();
  Q('.pages').scrollTop = 0;
}
QA('.nav-item').forEach((b) => b.addEventListener('click', () => go(b.dataset.page)));

function refreshBadge() {
  const f = S.files[S.page];
  const el = Q('#fileBadge');
  if (S.page === 'about') { el.textContent = '本地运行 · v' + APP_VERSION; el.classList.remove('on'); return; }
  if (f) { el.textContent = `${f.name} · ${fmtSize(f.size)}`; el.classList.add('on'); }
  else { el.textContent = '未选择文件'; el.classList.remove('on'); }
}

/* ------------------------------ 拖放 / 选择 ------------------------------ */
let dragDepth = 0;
const overlay = Q('#overlay');
window.addEventListener('dragenter', (e) => {
  if (!e.dataTransfer || !Array.from(e.dataTransfer.types).includes('Files')) return;
  e.preventDefault(); dragDepth++; overlay.classList.add('on');
});
window.addEventListener('dragover', (e) => { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
window.addEventListener('dragleave', (e) => {
  e.preventDefault(); dragDepth = Math.max(0, dragDepth - 1);
  if (!dragDepth) overlay.classList.remove('on');
});
window.addEventListener('drop', (e) => {
  e.preventDefault(); dragDepth = 0; overlay.classList.remove('on');
  const page = S.page === 'about' ? 'icon' : S.page;
  const f = e.dataTransfer.files && e.dataTransfer.files[0];
  if (f) acceptFile(page, f);
});

QA('.drop').forEach((dz) => {
  const page = dz.dataset.page;
  dz.addEventListener('click', () => openPicker(page));
  dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('over'));
  dz.addEventListener('drop', (e) => { e.preventDefault(); dz.classList.remove('over'); });
});
QA('[data-pick]').forEach((b) => b.addEventListener('click', (e) => {
  e.stopPropagation(); openPicker(b.dataset.pick);
}));

function openPicker(page) {
  const input = Q('#picker');
  input.value = '';
  input.onchange = () => { if (input.files[0]) acceptFile(page, input.files[0]); };
  input.click();
}

function setBar(dz, p) {
  const bar = dz.querySelector('.drop-bar i');
  if (bar) bar.style.width = Math.min(100, Math.round(p * 100)) + '%';
}

async function acceptFile(page, file) {
  const okPe = /\.(exe|dll|scr|cpl|ocx|sys)$/i.test(file.name);
  const okApk = /\.(apk|xapk|apks)$/i.test(file.name);
  if (page === 'apk' ? !okApk : !okPe) {
    stamp(page === 'apk' ? '只支持 APK 文件' : '只支持 EXE / DLL / SCR / CPL / OCX / SYS 文件', 'WARN');
    return;
  }
  const dz = Q('#drop-' + page);
  dz.classList.add('loading');
  setBar(dz, 0);
  stamp(`正在读取 ${file.name}（${fmtSize(file.size)}）…`, 'DIM');
  try {
    const r = await upload(file, (p) => setBar(dz, p));
    setBar(dz, 1);
    S.files[page] = { ...r, file };
    stamp(`已载入 ${r.name}`, 'OK');
    refreshBadge();
    if (page === 'icon') await loadIcon();
    if (page === 'upx') loadUpx();
    if (page === 'vm') loadVm();
    if (page === 'apk') await loadApk();
  } catch (e) {
    stamp('读取失败：' + e.message, 'ERR');
  } finally {
    dz.classList.remove('loading');
  }
}

function resetPage(page) {
  S.files[page] = null;
  Q('#drop-' + page).hidden = false;
  Q('#ws-' + page).hidden = true;
  refreshBadge();
}
Q('#btnIconRe').addEventListener('click', () => resetPage('icon'));
Q('#btnUpxRe').addEventListener('click', () => resetPage('upx'));
Q('#btnVmRe').addEventListener('click', () => resetPage('vm'));
Q('#btnApkRe').addEventListener('click', () => resetPage('apk'));

/* ------------------------------ 图标提取 ------------------------------ */
async function loadIcon() {
  const f = S.files.icon;
  Q('#drop-icon').hidden = true;
  Q('#ws-icon').hidden = false;
  Q('#iconResult').hidden = true;
  refreshBadge();
  try {
    const r = await apiPost('/api/probe', { fid: f.fid });
    Q('#iconOutdir').value = r.outdir;
    renderMeta(r.summary);
    renderIcons(r);
  } catch (e) {
    stamp('解析失败：' + e.message, 'ERR');
  }
}

function metaItem(label, value, cls) {
  return `<div class="meta-item"><i>${label}</i><b>${value}</b></div>`;
}
function renderMeta(s) {
  const tags = s.sections.map((x) => `<span class="tag">${esc(x)}</span>`).join(' ');
  const flags = [
    s.upx ? '<span class="tag warn">UPX 已加壳</span>' : '<span class="tag ok">未加壳</span>',
    s.dotnet ? '<span class="tag">.NET</span>' : '',
    s.resource ? '<span class="tag">含资源</span>' : '<span class="tag bad">无资源</span>',
  ].join(' ');
  Q('#metaGrid').innerHTML = [
    metaItem('文件名', esc(s.path.split(/[\\/]/).pop())),
    metaItem('大小', fmtNum(s.size) + ' 字节'),
    metaItem('架构', esc(s.machine)),
    metaItem('格式', esc(s.pe_type)),
    metaItem('入口点', esc(s.entry_point)),
    metaItem('映像基址', esc(s.image_base)),
    `<div class="meta-item" style="grid-column:1/-1"><i>节区</i><b style="white-space:normal">${tags}</b></div>`,
    `<div class="meta-item" style="grid-column:1/-1"><i>状态</i><b style="white-space:normal">${flags}</b></div>`,
  ].join('');
}

function renderIcons(r) {
  const grid = Q('#iconGrid');
  grid.innerHTML = '';
  const groups = r.groups || [];
  Q('#iconCount').textContent = groups.length
    ? `${groups.length} 组 · ${groups.reduce((a, g) => a + g.count, 0)} 个尺寸`
    : '没有找到图标资源';

  if (!groups.length) {
    grid.innerHTML = '<p class="para tiny">这个文件里没有 RT_GROUP_ICON 资源，通常意味着图标被剥离或被上层程序动态设置。</p>';
    Q('#bigPreview').innerHTML = '<span>无图标</span>';
    return;
  }

  const fid = r.fid;
  groups.forEach((g) => {
    const wrap = document.createElement('div');
    wrap.className = 'icon-group';
    let tag = g.name || '';
    tag = tag.startsWith('图标组 #') ? ' · ' + tag.slice(4) : (tag ? ' · ' + esc(tag) : '');
    wrap.innerHTML = `<h4>图标组 #${g.index + 1}${tag} · ${g.count} 个尺寸</h4>`;
    const list = document.createElement('div');
    list.className = 'icons-grid';
    g.entries.forEach((e, i) => {
      const src = `/api/icon?fid=${fid}&g=${g.index}&i=${i}&t=${encodeURIComponent(TOKEN)}`;
      const tile = document.createElement('div');
      tile.className = 'tile';
      tile.innerHTML = `<img src="${src}" alt=""><b>${esc(e.size)}</b><span>${e.bits} bit</span>`;
      tile.addEventListener('mouseenter', () => {
        Q('#bigPreview').innerHTML = `<img src="${src}" alt="">`;
      });
      list.appendChild(tile);
    });
    wrap.appendChild(list);
    grid.appendChild(wrap);
  });

  // 默认预览最大的一张
  const first = groups[0];
  let best = 0;
  first.entries.forEach((e, i) => {
    const w = parseInt(e.size.split('x')[0], 10) || 0;
    const bw = parseInt(first.entries[best].size.split('x')[0], 10) || 0;
    if (w > bw) best = i;
  });
  Q('#bigPreview').innerHTML =
    `<img src="/api/icon?fid=${fid}&g=0&i=${best}&t=${encodeURIComponent(TOKEN)}" alt="">`;
}

async function exportIcons(ico, png) {
  const f = S.files.icon;
  if (!f) return;
  try {
    const res = await runJob('/api/icons', {
      fid: f.fid, outdir: Q('#iconOutdir').value.trim(), ico, png,
    }, (result) => renderIconResult(result));
    if (res) stamp(`已导出 ${res.files.length} 个文件`, 'OK');
  } catch (e) { /* 已在 runJob 记录 */ }
}

function renderIconResult(res) {
  const box = Q('#iconResult');
  box.hidden = false;
  const chips = res.files.map((x) =>
    `<span class="fchip" title="${esc(x.path)}">${esc(x.name)}<i>${fmtSize(x.size)}</i></span>`).join('');
  box.innerHTML = `
    <div class="res-head"><b>导出完成 · ${res.files.length} 个文件</b>
      <span class="spacer" style="flex:1"></span>
      <button class="mini" id="btnIconFolder">打开文件夹</button>
    </div>
    <div class="res-path">${esc(res.dir)}</div>
    <div class="files">${chips}</div>`;
  Q('#btnIconFolder').addEventListener('click', () => openPath(res.dir));
  focusResult(box);
}
Q('#btnIconAll').addEventListener('click', () => exportIcons(true, true));
Q('#btnIconIco').addEventListener('click', () => exportIcons(true, false));
Q('#btnIconPng').addEventListener('click', () => exportIcons(false, true));
Q('#btnIconOpen').addEventListener('click', () => openPath(Q('#iconOutdir').value.trim()));

async function openPath(p) {
  if (!p) return;
  try { await apiPost('/api/open', { path: p }); }
  catch (e) { stamp('打开失败：' + e.message, 'WARN'); }
}

/* ------------------------------ UPX ------------------------------ */
let upxMode = 'pack';
function loadUpx() {
  const f = S.files.upx;
  Q('#drop-upx').hidden = true;
  Q('#ws-upx').hidden = false;
  Q('#upxResult').hidden = true;
  Q('#upxFileInfo').textContent = `${f.name} · ${fmtSize(f.size)}`;
  Q('#upxOutdir').value = S.outdir || '';
  syncUpxMode();
}
function syncUpxMode() {
  const seg = QA('#upxMode .seg').find((b) => b.dataset.mode === upxMode);
  QA('#upxMode .seg').forEach((b) => b.classList.toggle('active', b.dataset.mode === upxMode));
  Q('#upxOptions').hidden = upxMode !== 'pack';
  const nameEl = Q('#upxOutname');
  const f = S.files.upx;
  const base = f ? stem(f.name) : 'output';
  if (upxMode === 'pack') nameEl.value = base + '_upx.exe';
  else if (upxMode === 'unpack') nameEl.value = base + '_unpacked.exe';
  nameEl.closest('.field-row').hidden = !(upxMode === 'pack' || upxMode === 'unpack');
  Q('#btnUpxRun').textContent = {
    pack: '开始压缩', unpack: '脱壳还原', test: '执行完整性测试',
    list: '查看压缩信息', fileinfo: '查看壳参数',
  }[upxMode];
  // 只读模式下不显示图标/附加参数等压缩选项
  Q('#upxOptions').hidden = upxMode !== 'pack';
  if (seg) seg.classList.add('active');
}
QA('#upxMode .seg').forEach((b) => b.addEventListener('click', () => {
  upxMode = b.dataset.mode;
  syncUpxMode();
}));

const lvl = Q('#upxLevel');
function syncLevel() {
  Q('#upxLevelVal').textContent = lvl.value;
  lvl.style.setProperty('--p', ((lvl.value - 1) / 8 * 100) + '%');
}
lvl.addEventListener('input', syncLevel);
Q('#upxBest').addEventListener('change', () => { lvl.disabled = Q('#upxBest').checked || Q('#upxBrute').checked; });
Q('#upxBrute').addEventListener('change', () => { lvl.disabled = Q('#upxBest').checked || Q('#upxBrute').checked; });
Q('#btnUpxOpen').addEventListener('click', () => openPath(Q('#upxOutdir').value.trim()));

Q('#btnUpxRun').addEventListener('click', async () => {
  const f = S.files.upx;
  if (!f) return;
  const opts = {
    level: parseInt(lvl.value, 10),
    best: Q('#upxBest').checked,
    brute: Q('#upxBrute').checked,
    lzma: Q('#upxLzma').checked,
    force: Q('#upxForce').checked,
    icons: parseInt(Q('#upxIcons').value, 10),
    noRes: Q('#upxNoRes').checked,
    keepReloc: Q('#upxReloc').checked,
    extra: Q('#upxExtra').value.trim(),
  };
  stamp(`开始 ${upxMode}：${f.name}`, 'DIM');
  try {
    const res = await runJob('/api/upx', {
      fid: f.fid, mode: upxMode, opts,
      outdir: Q('#upxOutdir').value.trim(),
      outname: Q('#upxOutname').value.trim(),
    }, (r) => renderUpxResult(r));
    if (res) stamp('处理完成', 'OK');
  } catch (e) { /* ignore */ }
});

function renderUpxResult(r) {
  const box = Q('#upxResult');
  box.hidden = false;
  if (r.path) {
    box.innerHTML = `
      <div class="stat-row">
        <div class="stat"><i>原始大小</i><b>${fmtNum(r.size_before)}</b></div>
        <div class="stat"><i>处理后</i><b class="up">${fmtNum(r.size_after)}</b></div>
        <div class="stat"><i>体积变化</i><b class="up">${r.ratio > 0 ? '-' : '+'}${Math.abs(r.ratio)}%</b></div>
      </div>
      <div class="res-path">${esc(r.path)}</div>
      <div class="files"><span class="fchip">${esc(r.name)}<i>${fmtSize(r.size_after)}</i></span></div>
      <div class="btn-row">
        <button class="mini" id="btnUpxFolder">打开所在文件夹</button>
        <a class="mini" style="line-height:26px;text-decoration:none"
           href="/api/file?path=${encodeURIComponent(r.path)}&t=${encodeURIComponent(TOKEN)}">下载</a>
      </div>`;
    Q('#btnUpxFolder').addEventListener('click', () => openPath(r.path));
  } else {
    box.innerHTML = `<div class="res-head"><b>执行结果</b></div>
      <pre class="res-path" style="white-space:pre-wrap;line-height:1.6">${esc((r.lines || []).join('\n'))}</pre>`;
  }
  focusResult(box);
}

/* ------------------------------ VM ------------------------------ */
function loadVm() {
  const f = S.files.vm;
  Q('#drop-vm').hidden = true;
  Q('#ws-vm').hidden = false;
  Q('#vmResult').hidden = true;
  Q('#vmFileInfo').textContent = `${f.name} · ${fmtSize(f.size)}`;
  Q('#vmOutdir').value = S.outdir || '';
  Q('#vmOutname').value = stem(f.name) + '_vm.exe';
}
QA('#vmJunk .opt').forEach((l) => l.addEventListener('click', () => {
  QA('#vmJunk .opt').forEach((x) => x.classList.remove('active'));
  l.classList.add('active');
}));
Q('#btnVmOpen').addEventListener('click', () => openPath(Q('#vmOutdir').value.trim()));

Q('#btnVmRun').addEventListener('click', async () => {
  const f = S.files.vm;
  if (!f) return;
  const junk = parseInt((QA('input[name="junk"]').find((x) => x.checked) || {}).value || '0', 10);
  const opts = {
    junk,
    password: Q('#vmPass').value,
    extraArgs: Q('#vmArgs').value.trim(),
    verify: Q('#vmVerify').checked,
    cleanup: Q('#vmCleanup').checked,
    forwardArgs: Q('#vmForward').checked,
    keepIcon: Q('#vmIcon').checked,
  };
  stamp(`开始生成保护副本：${f.name}`, 'DIM');
  try {
    const res = await runJob('/api/vm', {
      fid: f.fid, opts,
      outdir: Q('#vmOutdir').value.trim(),
      outname: Q('#vmOutname').value.trim(),
    }, (r) => renderVmResult(r));
    if (res) stamp('生成完成', 'OK');
  } catch (e) { /* ignore */ }
});

function renderVmResult(r) {
  const box = Q('#vmResult');
  box.hidden = false;
  box.innerHTML = `
    <div class="stat-row">
      <div class="stat"><i>原始大小</i><b>${fmtNum(r.size_before)}</b></div>
      <div class="stat"><i>加壳后</i><b>${fmtNum(r.size_after)}</b></div>
      <div class="stat"><i>虚拟指令</i><b>${fmtNum(r.program_size)}</b></div>
      <div class="stat"><i>构建指纹</i><b style="font-family:Consolas,monospace;font-size:12.5px">${esc(r.fingerprint || '')}</b></div>
    </div>
    <div class="res-path">${esc(r.path)}</div>
    <div class="btn-row">
      <button class="mini" id="btnVmFolder">打开所在文件夹</button>
      <a class="mini" style="line-height:26px;text-decoration:none"
         href="/api/file?path=${encodeURIComponent(r.path)}&t=${encodeURIComponent(TOKEN)}">下载</a>
    </div>`;
  Q('#btnVmFolder').addEventListener('click', () => openPath(r.path));
  focusResult(box);
}

/* ------------------------------ APK 加固 ------------------------------ */
async function loadApk() {
  const f = S.files.apk;
  Q('#drop-apk').hidden = true;
  Q('#ws-apk').hidden = false;
  Q('#apkResult').hidden = true;
  Q('#apkFileInfo').textContent = `${f.name} · ${fmtSize(f.size)}`;
  Q('#apkOutdir').value = S.outdir || '';
  Q('#apkOutname').value = stem(f.name) + '_protected.apk';
  Q('#apkMeta').innerHTML = '<div class="meta-item"><i>状态</i><b>解析中…</b></div>';
  Q('#apkWarn').hidden = true;
  try {
    await runJob('/api/apk/inspect', { fid: f.fid }, (r) => renderApkInfo(r));
  } catch (e) { /* 已在日志里提示 */ }
}

function renderApkInfo(r) {
  const sig = r.signature || {};
  const abis = Object.entries(r.abis || {});
  const items = [
    ['包名', r.package || '—'],
    ['版本', `${r.version_name || '—'}（${r.version_code || 0}）`],
    ['SDK', `min ${r.min_sdk == null ? '—' : r.min_sdk} / target ${r.target_sdk == null ? '—' : r.target_sdk}`],
    ['安装包大小', fmtSize(r.size)],
    ['dex', `${r.dexes.length} 个 · ${fmtSize(r.entry.dex_bytes)}`],
    ['条目总数', fmtNum(r.entry.count)],
    ['原生库 ABI', abis.length ? abis.map(([k, v]) => `${k}×${v}`).join('　') : '无'],
    ['签名方案', (sig.schemes || []).length ? sig.schemes.join(' + ') : '未签名'],
    ['签名证书', sig.dn || '—'],
    ['入口 Application', r.app_class || '系统默认'],
  ];
  Q('#apkMeta').innerHTML = items.map(([k, v]) =>
    `<div class="meta-item"><i>${esc(k)}</i><b title="${esc(v)}">${esc(v)}</b></div>`).join('');

  const warn = Q('#apkWarn');
  const list = (r.warnings || []).slice();
  if (list.length) {
    warn.hidden = false;
    warn.innerHTML = list.map((w) => `<span class="tag warn">${esc(w)}</span>`).join('');
  } else {
    warn.hidden = true;
  }
  const t = r.tools || {};
  Q('#apkTools').textContent = t.ok
    ? `工具链 ${t.build_tools} · ${t.platform}`
    : '工具链缺失：' + (t.missing || []).join('、');
}

QA('#apkLevel .opt').forEach((l) => l.addEventListener('click', () => {
  QA('#apkLevel .opt').forEach((x) => x.classList.remove('active'));
  l.classList.add('active');
}));

Q('#apkKeystore').addEventListener('input', () => {
  Q('#apkKsRow').hidden = !Q('#apkKeystore').value.trim();
});
Q('#btnApkOpen').addEventListener('click', () => openPath(Q('#apkOutdir').value.trim()));

Q('#btnApkRun').addEventListener('click', async () => {
  const f = S.files.apk;
  if (!f) return;
  const level = ((QA('input[name="apkLevel"]').find((x) => x.checked) || {}).value) || 'strong';
  const opts = {
    level,
    stripDebug: Q('#apkStripDebug').checked,
    hardenBackup: Q('#apkBackup').checked,
    debug: Q('#apkDebug').checked,
    keystore: Q('#apkKeystore').value.trim(),
    ksAlias: Q('#apkKsAlias').value.trim(),
    ksPass: Q('#apkKsPass').value,
    keyPass: Q('#apkKeyPass').value,
  };
  stamp(`开始加固：${f.name}（${level}）`, 'DIM');
  try {
    const res = await runJob('/api/apk/protect', {
      fid: f.fid, opts,
      outdir: Q('#apkOutdir').value.trim(),
      outname: Q('#apkOutname').value.trim(),
    }, (r) => renderApkResult(r));
    if (res) stamp('加固完成，产物自检全部通过', 'OK');
  } catch (e) { /* ignore */ }
});

function renderApkResult(r) {
  const box = Q('#apkResult');
  box.hidden = false;
  const checks = Object.entries(r.checks || {})
    .map(([k, v]) => `<span class="tag ${v ? 'ok' : 'warn'}">${esc(k)}${v ? ' ✓' : ' ✗'}</span>`).join('');
  box.innerHTML = `
    <div class="stat-row">
      <div class="stat"><i>加固前</i><b>${fmtNum(r.size_before)}</b></div>
      <div class="stat"><i>加固后</i><b>${fmtNum(r.size_after)}</b></div>
      <div class="stat"><i>载荷分段</i><b>${fmtNum(r.payload_parts)}</b></div>
      <div class="stat"><i>耗时</i><b>${r.elapsed} 秒</b></div>
    </div>
    <div class="tag-row">${checks}</div>
    <div class="res-path">${esc(r.path)}</div>
    <div class="btn-row">
      <button class="mini" id="btnApkFolder">打开所在文件夹</button>
      <a class="mini" style="line-height:26px;text-decoration:none"
         href="/api/file?path=${encodeURIComponent(r.path)}&t=${encodeURIComponent(TOKEN)}">下载</a>
    </div>`;
  Q('#btnApkFolder').addEventListener('click', () => openPath(r.path));
  focusResult(box);
}

/* ------------------------------ 环境信息 ------------------------------ */
async function loadEnv() {
  try {
    const e = await apiGet('/api/env');
    S.outdir = e.outdir;
    const u = Q('#envUpx');
    if (e.upx.found) {
      u.innerHTML = `<i class="dot"></i>${esc(e.upx.version.replace(/^upx\s*/i, 'UPX '))}`;
      u.title = e.upx.path;
    } else {
      u.classList.add('bad');
      u.innerHTML = '<i class="dot"></i>内置 UPX 缺失';
    }
    const b = Q('#envBackend');
    if (e.backend.ok) {
      b.innerHTML = '<i class="dot"></i>编译后端就绪';
      b.title = e.backend.info;
    } else {
      b.classList.add('bad');
      b.innerHTML = '<i class="dot"></i>VM 编译后端不可用';
      b.title = e.backend.info;
    }
    Q('#vmBackend').textContent = e.backend.ok ? '外壳编译器就绪' : '需要 Python + PyInstaller';
    const a = Q('#envAndroid');
    const aBundled = !!(e.android && e.android.bundled);
    if (e.android && e.android.ok) {
      a.innerHTML = `<i class="dot"></i>Android ${esc(e.android.build_tools)}${aBundled ? ' · 内置' : ''}`;
      a.title = 'platform ' + e.android.platform + (aBundled ? '（随程序分发，无需安装 SDK）' : '');
    } else if (a) {
      a.classList.add('bad');
      a.innerHTML = '<i class="dot"></i>Android 工具链缺失';
      a.title = (e.android && e.android.missing || []).join('、');
    }
    Q('#apkTools').textContent = (e.android && e.android.ok)
      ? `${aBundled ? '内置工具链' : '本机工具链'} ${e.android.build_tools} · ${e.android.platform}`
      : '未检测到 Android SDK';
    Q('#aboutVer').textContent = 'v' + APP_VERSION + ' · Python ' + e.python;
    Q('#aboutGrid').innerHTML = [
      metaItem('内置 UPX', esc(e.upx.version.split(/[\r\n]/)[0] || '未检测到')),
      metaItem('编译后端', esc(e.backend.ok ? '可用' : '不可用')),
      metaItem('Android 工具链', esc(e.android && e.android.ok
        ? e.android.build_tools + (aBundled ? '（内置）' : '')
        : '不可用')),
      metaItem('运行方式', e.frozen ? '独立 EXE' : 'Python 源码'),
      metaItem('默认输出', esc(e.outdir)),
    ].join('');
    ['#iconOutdir', '#upxOutdir', '#vmOutdir', '#apkOutdir'].forEach((sel) => {
      if (!Q(sel).value) Q(sel).value = e.outdir;
    });
  } catch (err) {
    stamp('环境信息读取失败：' + err.message, 'WARN');
  }
}

/* ------------------------------ 控制 ------------------------------ */
Q('#btnClear').addEventListener('click', () => { LOG_BOX().innerHTML = ''; });
Q('#btnFold').addEventListener('click', () => {
  const c = Q('#console');
  c.classList.toggle('folded');
  Q('#btnFold').textContent = c.classList.contains('folded') ? '展开' : '收起';
});
Q('#btnQuit').addEventListener('click', async () => {
  try { await apiPost('/api/quit', {}); } catch (e) { /* ignore */ }
  document.body.innerHTML =
    '<div style="height:100vh;display:flex;align-items:center;justify-content:center;' +
    'font-family:Segoe UI,sans-serif;color:#64748b;font-size:14px">' +
    '服务已停止，可以关闭这个窗口了。</div>';
  setTimeout(() => window.close(), 200);
});

setInterval(() => { fetch('/api/ping', { method: 'POST' }).catch(() => {}); }, 5000);

/* ------------------------------ 启动 ------------------------------ */
syncLevel();
syncUpxMode();
go('icon');
loadEnv();
stamp('CyrilShield v' + APP_VERSION + ' 就绪，把文件拖进窗口即可开始', 'OK');
