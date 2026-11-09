'use strict';

const paths = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  history: '<path d="M3 10a9 9 0 1 1 2 8M3 4v6h6M12 7v5l3 2"/>',
  monitor: '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  layers: '<path d="m12 3 10 5-10 5L2 8l10-5Zm-9 9 9 5 9-5M3 16l9 5 9-5"/>',
  help: '<circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 0 1 5 0c0 2-2.5 2-2.5 4m0 3h.01"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.2 6a8 8 0 0 1 13.4 3M4.4 15a8 8 0 0 0 13.4 3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  activity: '<path d="M2 12h4l3-8 5 16 3-8h5"/>',
  server: '<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01m4-11h6m-6 11h6"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>',
  link: '<path d="m10 13 4-4m-6 6-1 1a3.5 3.5 0 0 1-5-5l4-4a3.5 3.5 0 0 1 5 0m2 2 1-1a3.5 3.5 0 0 1 5 5l-4 4a3.5 3.5 0 0 1-5 0"/>',
  'arrow-right': '<path d="M4 12h16m-6-6 6 6-6 6"/>',
  arrows: '<path d="M3 7h16m-5-5 5 5-5 5M21 17H5m5-5-5 5 5 5"/>',
  globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  'check-circle': '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
  x: '<path d="m6 6 12 12M6 18 18 6"/>',
  edit: '<path d="m15 4 5 5M4 20l5-1L21 7a2.1 2.1 0 0 0-5-5L4 14l-1 7 7-1"/>',
  file: '<path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9l-6-6Z"/><path d="M14 3v6h6M8 13h8m-8 4h6"/>',
  more: '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
  copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
  power: '<path d="M12 2v10m-6-7a9 9 0 1 0 12 0"/>',
  terminal: '<path d="m4 6 6 6-6 6m9 0h7"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  alert: '<path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v4m0 4h.01"/>',
};
const icon = name => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths[name] || paths.link}</svg>`;
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const $ = id => document.getElementById(id);
function hydrateIcons(root = document) { root.querySelectorAll('[data-icon]').forEach(el => { el.innerHTML = icon(el.dataset.icon); }); }
hydrateIcons();

let token = localStorage.getItem('tunneldesk.access') || '';
const fragment = new URLSearchParams(location.hash.slice(1));
if (fragment.has('token')) {
  token = fragment.get('token');
  localStorage.setItem('tunneldesk.access', token);
  history.replaceState(null, '', location.pathname);
}
let state = {tunnels: [], aliases: [], events: [], jobs: []};
let filter = 'all', view = 'overview', query = '', editingId = null, inspectId = null, inspectTab = 'log';
let confirmCallback = null, loading = false, firstLoad = true;
const watchedJobs = new Set();
let renderFingerprint = '';

async function api(path, {method = 'GET', body} = {}) {
  const headers = {'Authorization': `Bearer ${token}`, 'X-Tunnel-Desk': '1'};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, {method, headers, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'omit', cache: 'no-store'});
  const result = await response.json();
  if (response.status === 401 || response.status === 403) {
    if (response.status === 401) $('auth-screen').hidden = false;
  }
  if (!response.ok) throw new Error(result.error || '请求未完成');
  return result;
}

function toast(message, error = false) {
  const el = document.createElement('div');
  el.className = `toast${error ? ' error' : ''}`;
  el.innerHTML = `${icon(error ? 'alert' : 'check-circle')}<span>${esc(message)}</span>`;
  $('toasts').append(el);
  setTimeout(() => el.remove(), error ? 9000 : 5500);
}

function running(t) { return t.status === 'running' || t.status === 'connecting'; }
function timeLabel(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleTimeString('zh-CN', {hour12: false});
}
function hostLabel(t) { return t.resolved?.hostname || t.target.split('@').pop(); }
function sourceLabel(t) { return {launchd: '系统托管', existing: '现有连接', app: '应用管理'}[t.source] || '应用管理'; }
function sourceDescription(t) { return t.source === 'launchd' ? '由 macOS launchd 维护；开关会同步控制系统任务' : t.source === 'existing' ? '已接入现有 SSH 进程，未中断原连接' : '由 Tunnel Desk 启动并记录日志'; }

function card(t) {
  const route = t.active_connection || t;
  const isRunning = running(t);
  const label = {running:'运行中', stopped:'已关闭', connecting:'连接中', error:'连接异常'}[t.status] || '未知';
  const health = t.health;
  const healthLevel = health ? health.level || (health.ok ? 'good' : 'bad') : '';
  const remoteEntry = route.kind === 'R';
  const leftHost = remoteEntry ? hostLabel(route) : '这台电脑';
  const rightHost = remoteEntry ? (['127.0.0.1','::1','localhost'].includes(route.dest_host) ? '这台电脑' : route.dest_host) : route.kind === 'D' ? hostLabel(route) : route.dest_host;
  const leftCaption = remoteEntry ? '远端入口' : '本机入口';
  const rightCaption = route.kind === 'D' ? 'SOCKS 出口' : remoteEntry ? '本机可访问的目标' : '远端可访问的目标';
  const rightAddress = route.kind === 'D' ? '经远端访问网络' : `${esc(route.dest_host)}:<strong>${esc(route.dest_port)}</strong>`;
  const healthText = !isRunning ? '连接关闭，检测尚未运行' : health ? health.message : '链路尚未检测';
  const stateItem = t.local_service === null ? '' : `<span class="state-item ${t.local_service ? 'good' : 'bad'}">${icon(t.local_service ? 'check-circle' : 'alert')}本机目标${t.local_service ? '可连接' : '不可达'}</span>`;
  return `<article class="tunnel-card" data-tunnel="${esc(t.id)}">
    ${t.pending_changes ? '<div class="pending-label">配置已更新，重启后生效；当前连接仍使用原配置。</div>' : ''}
    <div class="card-top"><span class="tunnel-symbol ${t.dest_port === 8317 ? 'blue' : ''}">${icon(t.kind === 'D' ? 'globe' : 'arrows')}</span><div class="card-title-area"><div class="card-title-line"><h2>${esc(t.name)}</h2><span class="source-badge" title="${esc(sourceDescription(t))}">${esc(sourceLabel(t))}</span></div><p>${esc(t.description || `${t.kind === 'R' ? '反向转发' : t.kind === 'L' ? '本地转发' : '动态 SOCKS'} · ${t.target}`)}</p></div><div class="card-toggle-area"><span class="status-label ${esc(t.status)}"><span class="tiny-dot"></span>${label}</span><button class="switch" role="switch" aria-checked="${isRunning}" aria-label="${isRunning ? '关闭' : '开启'} ${esc(t.name)}" data-action="toggle" data-id="${t.id}" ${t.busy ? 'disabled' : ''}></button></div></div>
    <div class="route"><div class="route-endpoint"><span class="route-caption">${leftCaption}</span><div class="route-host">${icon(remoteEntry ? 'server' : 'monitor')}<span title="${esc(leftHost)}">${esc(leftHost)}</span></div><div class="route-address">${esc(route.bind_host)}:<strong>${route.bind_port}</strong></div></div><div class="route-arrow"><div class="route-line">${icon('arrow-right')}</div><span class="route-hop" title="${esc(route.jump || '直接 SSH 连接')}">${route.jump ? '经跳板机' : 'SSH'}</span></div><div class="route-endpoint"><span class="route-caption">${rightCaption}</span><div class="route-host">${icon(remoteEntry ? 'monitor' : 'server')}<span>${esc(rightHost)}</span></div><div class="route-address">${rightAddress}</div></div></div>
    <div class="card-state"><span class="state-item ${isRunning ? 'good' : ''}">${icon(isRunning ? 'link' : 'clock')}${isRunning ? 'SSH ' + (t.status === 'connecting' ? '正在认证' : '已连接') : 'SSH 未连接'}${t.pid ? `<span class="pid">PID ${t.pid}</span>` : ''}</span>${stateItem}</div>
    ${t.last_error && !isRunning ? `<div class="card-error">${esc(t.last_error)}</div>` : ''}
    <div class="card-footer"><button class="health-summary ${healthLevel}" data-action="health" data-id="${t.id}" title="${esc(healthText)}；点击查看检测详情">${icon(t.busy ? 'clock' : health ? healthLevel === 'good' ? 'shield' : 'alert' : 'info')}<span>${t.busy ? '操作处理中…' : esc(healthText)}</span></button><div class="card-actions"><button class="check-button" data-action="check" data-id="${t.id}" ${!isRunning || t.busy || t.pending_changes ? 'disabled' : ''}>${icon('activity')}检测链路</button><button class="icon-button" data-action="edit" data-id="${t.id}" aria-label="编辑 ${esc(t.name)}" title="编辑配置">${icon('edit')}</button><button class="icon-button" data-action="logs" data-id="${t.id}" aria-label="查看 ${esc(t.name)} 日志" title="查看日志">${icon('file')}</button><details class="card-menu"><summary aria-label="${esc(t.name)} 更多操作">${icon('more')}</summary><div class="card-menu-panel"><button data-action="restart" data-id="${t.id}" ${t.busy || !isRunning ? 'disabled' : ''}>${icon('refresh')}重启连接</button><button data-action="clone" data-id="${t.id}">${icon('copy')}复制配置</button><button class="delete" data-action="delete" data-id="${t.id}" ${t.source === 'launchd' ? 'disabled title="保留原系统任务；可以关闭通道"' : ''}>${icon('trash')}移除配置</button></div></details></div></div>
  </article>`;
}

function render() {
  const tunnels = state.tunnels;
  $('stat-total').textContent = tunnels.length;
  $('stat-running').textContent = tunnels.filter(running).length;
  const services = [...new Map(tunnels.map(t => ({...t, ...(t.active_connection || {})})).filter(t => t.kind === 'R' && t.local_service !== null).map(t => [`${t.dest_host}:${t.dest_port}`, t])).values()];
  $('stat-services').textContent = services.filter(t => t.local_service).length;
  $('stat-healthy').textContent = tunnels.filter(t => running(t) && t.health?.ok).length;
  $('nav-count').textContent = tunnels.length;
  $('filter-all').textContent = tunnels.length;
  $('filter-running').textContent = tunnels.filter(running).length;
  $('filter-stopped').textContent = tunnels.filter(t => !running(t)).length;
  $('sync-time').textContent = `最近同步 ${timeLabel(state.updated_at)}`;
  $('backend-badge-text').textContent = ({launchd:'后台由 launchd 托管',task_scheduler:'后台由任务计划程序托管'}[state.backend?.managed_by] || '本机后台运行中');
  const selected = tunnels.filter(t => (filter === 'all' || (filter === 'running' ? running(t) : !running(t))) && `${t.name} ${t.description} ${t.target} ${hostLabel(t)} ${t.bind_port} ${t.dest_port || ''}`.toLowerCase().includes(query));
  // Avoid replacing an open menu or focused control on every polling tick.
  const fingerprint = JSON.stringify([selected, view, filter, query]);
  if (fingerprint !== renderFingerprint) {
    renderFingerprint = fingerprint;
    $('tunnel-list').innerHTML = selected.length ? selected.map(card).join('') : `<div class="empty-state"><span class="empty-symbol">${icon('layers')}</span><h3>${tunnels.length ? '没有匹配的通道' : '把第一条连接带进来'}</h3><p>${tunnels.length ? '换一个关键词，或查看其他状态。' : '发现已有 SSH 隧道，或创建一条新的转发。'}</p>${tunnels.length ? '' : '<button class="button primary" data-action="new">新建通道</button>'}</div>`;
  }
  $('services-list').innerHTML = services.length ? services.map(t => `<div class="service-row"><span class="service-symbol">${icon(t.dest_port === 8317 ? 'terminal' : 'globe')}</span><div class="service-info"><strong>${t.dest_port === 8317 ? 'CLIProxyAPI · 模型接口' : t.dest_port === 7897 ? '本机网络代理' : '本机目标服务'}</strong><code>${esc(t.dest_host)}:${t.dest_port}</code></div><span class="service-state ${t.local_service ? '' : 'offline'}" title="${t.local_service ? 'TCP 可连接' : 'TCP 不可连接'}"></span></div>`).join('') : '<p class="panel-intro">添加反向转发后，将在这里显示本机目标。</p>';
  $('activity-list').innerHTML = state.events.length ? state.events.map(e => `<div class="activity-row"><span class="activity-symbol">${icon('check')}</span><span class="activity-message">${esc(e.message)}</span><span class="activity-time">${timeLabel(e.time)}</span></div>`).join('') : '<div class="empty-state">本次会话暂无活动。</div>';
  $('ssh-hosts').innerHTML = state.aliases.map(alias => `<option value="${esc(alias)}"></option>`).join('');
  if (state.scan_error) { $('connection-notice').textContent = state.scan_error; $('connection-notice').hidden = false; }
}

async function refresh() {
  if (loading || !token) return;
  loading = true;
  try {
    state = await api('/api/state');
    $('auth-screen').hidden = true;
    $('connection-notice').hidden = !state.scan_error;
    for (const job of state.jobs) {
      if (watchedJobs.has(job.id) && job.status !== 'running') {
        watchedJobs.delete(job.id);
        const health = job.action === 'check' ? state.tunnels.find(t => t.id === job.tunnel_id)?.health : null;
        toast(job.message, job.status === 'error' || (health?.level === 'bad') || (health?.ok === false && !health.level));
        if (health?.level === 'bad') showInspector(job.tunnel_id, 'health');
      }
    }
    render();
    firstLoad = false;
  } catch (error) {
    if (!$('auth-screen').hidden) return;
    $('connection-notice').textContent = `管理后台暂时不可达。已有 SSH 隧道可能仍在运行；请重新打开启动器。${firstLoad ? ' ' + error.message : ''}`;
    $('connection-notice').hidden = false;
  } finally { loading = false; }
}

function setView(next) {
  view = next;
  document.querySelectorAll('[data-view]').forEach(button => button.classList.toggle('active', button.dataset.view === view));
  const title = {overview:'通道总览', activity:'最近活动'}[view];
  $('breadcrumb').textContent = title;
  $('page-title').innerHTML = `${title}<span class="title-dot">.</span>`;
  $('page-subtitle').textContent = {overview:'在这里开关、新建和编辑连接。关闭页面，隧道继续运行。', activity:'查看本次会话中的配置变更、连接操作与检测结果。'}[view];
  $('tunnel-view').hidden = view === 'activity';
  $('stats').hidden = view === 'activity';
  $('activity-view').hidden = view !== 'activity';
  render();
}

function showForm(tunnel = null, clone = false) {
  const form = $('profile-form');
  form.reset();
  editingId = tunnel && !clone ? tunnel.id : null;
  $('form-title').textContent = clone ? '复制通道' : tunnel ? '编辑通道' : '新建通道';
  const defaults = {name:'',description:'',kind:'R',target:'',ssh_port:'',jump:'',bind_host:'127.0.0.1',bind_port:'',dest_host:'127.0.0.1',dest_port:'',auth_mode:'key',auto_reconnect:false,health_type:'http_proxy',health_url:'https://www.baidu.com',identity_file:'',config_file:''};
  const data = {...defaults, ...(tunnel || {})};
  if (clone) { data.name += ' · 副本'; data.bind_port = ''; data.auto_reconnect = false; }
  for (const key of Object.keys(defaults)) {
    const field = form.elements.namedItem(key);
    if (field.type === 'checkbox') field.checked = !!data[key];
    else field.value = data[key] ?? '';
  }
  const launchd = tunnel?.source === 'launchd' && !clone;
  form.elements.namedItem('auth_mode').disabled = launchd;
  form.elements.namedItem('auto_reconnect').disabled = launchd;
  $('reconnect-help').textContent = launchd ? '此连接由系统任务负责保活；关闭开关会停用系统任务。' : '自动恢复使用 SSH 密钥 / ssh-agent；请先在 PowerShell 验证免交互登录。';
  $('source-notice').hidden = !launchd;
  $('source-notice').textContent = '已有系统任务将被保留。修改线路后，只有在你开启或重启时才应用；原任务会自动备份。';
  $('save-hint').textContent = tunnel && running(tunnel) && !clone ? '保存不会中断当前连接，修改在重启后生效。' : '保存配置后，手动开启连接。';
  $('form-error').hidden = true;
  updateForm();
  $('profile-dialog').showModal();
}

function updateForm() {
  const form = $('profile-form'), kind = form.elements.namedItem('kind').value;
  document.querySelectorAll('.destination-field').forEach(el => { el.hidden = kind === 'D'; });
  form.elements.namedItem('dest_port').required = kind !== 'D';
  $('bind-port-label').textContent = kind === 'R' ? '远端监听端口' : '本机 监听端口';
  $('destination-help').textContent = kind === 'R' ? '由 本机 连接这个目标地址' : '由远端服务器连接这个目标地址';
  $('health-url-field').hidden = form.elements.namedItem('health_type').value === 'tcp';
}

$('profile-form').addEventListener('submit', async event => {
  event.preventDefault();
  const form = event.currentTarget, data = {};
  for (const key of ['name','description','kind','target','ssh_port','jump','bind_host','bind_port','dest_host','dest_port','auth_mode','health_type','health_url','identity_file','config_file']) data[key] = form.elements.namedItem(key).value;
  data.auto_reconnect = form.elements.namedItem('auto_reconnect').checked;
  $('save-button').disabled = true;
  $('form-error').hidden = true;
  try {
    await api(editingId ? `/api/tunnels/${editingId}` : '/api/tunnels', {method:editingId ? 'PUT' : 'POST',body:data});
    $('profile-dialog').close();
    toast('配置已保存。当前运行的连接保持原样。');
    await refresh();
  } catch (error) {
    $('form-error').textContent = error.message;
    $('form-error').hidden = false;
    $('form-error').scrollIntoView({block:'nearest'});
  } finally { $('save-button').disabled = false; }
});
$('profile-form').addEventListener('change', updateForm);

function confirmAction(title, description, label, callback) {
  $('confirm-title').textContent = title;
  $('confirm-description').textContent = description;
  $('confirm-action').textContent = label;
  confirmCallback = callback;
  $('confirm-dialog').showModal();
}
$('confirm-action').addEventListener('click', () => {
  $('confirm-dialog').close();
  const action = confirmCallback;
  confirmCallback = null;
  if (action) action();
});

async function operate(id, action) {
  try {
    const job = await api(`/api/tunnels/${id}/${action}`, {method:'POST',body:{}});
    watchedJobs.add(job.id);
    if (action === 'start' || action === 'restart') toast('正在使用 SSH 密钥 / ssh-agent 建立连接。');
    if (action === 'check') toast('正在使用 SSH 密钥检测实际链路。');
    await refresh();
  } catch (error) { toast(error.message, true); }
}

async function showInspector(id, tab = 'log') {
  inspectId = id; inspectTab = tab;
  const tunnel = state.tunnels.find(t => t.id === id);
  if (!tunnel) return;
  $('inspect-title').textContent = tunnel.name;
  document.querySelectorAll('[data-inspect]').forEach(button => button.classList.toggle('active', button.dataset.inspect === tab));
  $('inspect-note').hidden = true;
  $('inspect-content').textContent = '正在读取…';
  if (!$('inspect-dialog').open) $('inspect-dialog').showModal();
  if (tab === 'log') {
    try { $('inspect-content').textContent = (await api(`/api/tunnels/${id}/logs`)).text; }
    catch (error) { $('inspect-content').textContent = error.message; }
  } else if (tab === 'health') {
    $('inspect-content').textContent = tunnel.health ? `[${tunnel.health.time}] ${tunnel.health.message}\n\n${tunnel.health.details}` : '尚未进行链路检测。开启通道后，点击卡片上的「检测链路」。';
  } else {
    $('inspect-note').hidden = false;
    $('inspect-note').textContent = '显示当前保存配置对应的命令。管理器直接调用 OpenSSH，不通过 Shell 执行用户输入。';
    $('inspect-content').textContent = tunnel.command;
  }
}

document.addEventListener('click', async event => {
  const close = event.target.closest('[data-close]');
  if (close) $(close.dataset.close).close();
  const nav = event.target.closest('[data-view]');
  if (nav) setView(nav.dataset.view);
  const tab = event.target.closest('[data-filter]');
  if (tab) {
    filter = tab.dataset.filter;
    document.querySelectorAll('[data-filter]').forEach(el => el.classList.toggle('active', el === tab));
    render();
  }
  const inspect = event.target.closest('[data-inspect]');
  if (inspect) showInspector(inspectId, inspect.dataset.inspect);
  const button = event.target.closest('[data-action]');
  if (!button || button.disabled) return;
  const {action, id} = button.dataset;
  if (action === 'new') return showForm();
  const t = state.tunnels.find(t => t.id === id);
  if (!t) return;
  button.closest('details')?.removeAttribute('open');
  if (action === 'edit') return showForm(t);
  if (action === 'clone') return showForm(t, true);
  if (action === 'logs') return showInspector(id);
  if (action === 'health') return showInspector(id, 'health');
  if (action === 'check') return operate(id, 'check');
  if (action === 'toggle') {
    if (running(t)) return confirmAction(`关闭「${t.name}」？`, `通过这条隧道的请求将会中断。${t.source === 'launchd' ? '\n系统保活任务也会停用，避免连接自动重生。' : ''}\n其他隧道及本机目标服务保持运行。`, '确认关闭', () => operate(id, 'stop'));
    return operate(id, 'start');
  }
  if (action === 'restart') return confirmAction(`重启「${t.name}」？`, '这条连接会短暂中断，然后按已保存的配置重新建立。', '确认重启', () => operate(id, 'restart'));
  if (action === 'delete') return confirmAction(`移除「${t.name}」？`, '请先关闭连接。这只移除本应用中的配置，不会删除 SSH 密钥或服务器文件。', '移除配置', async () => {
    try { await api(`/api/tunnels/${id}`, {method:'DELETE'}); toast('配置已移除'); await refresh(); }
    catch (error) { toast(error.message, true); }
  });
});

$('new-button').addEventListener('click', () => showForm());
$('search').addEventListener('input', event => { query = event.target.value.trim().toLowerCase(); render(); });
$('discover-button').addEventListener('click', async () => {
  $('discover-button').disabled = true;
  try {
    const result = await api('/api/discover', {method:'POST',body:{}});
    toast(result.added ? `已接入 ${result.added} 条通道，原连接保持运行。` : '已同步，暂无新的可接入通道。');
    await refresh();
  } catch (error) { toast(error.message, true); }
  finally { $('discover-button').disabled = false; }
});
['help-button','safety-help'].forEach(id => $(id).addEventListener('click', () => $('help-dialog').showModal()));
$('copy-inspect').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('inspect-content').textContent); toast('已复制'); }
  catch { toast('无法访问剪贴板，请手动选择并复制。', true); }
});
document.addEventListener('keydown', event => {
  if (event.key === '/' && !document.querySelector('dialog[open]') && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)) { event.preventDefault(); $('search').focus(); }
});
document.querySelectorAll('dialog').forEach(dialog => dialog.addEventListener('click', event => {
  if (event.target === dialog) { const rect = dialog.getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) dialog.close(); }
}));

if (!token) $('auth-screen').hidden = false;
else refresh();
setInterval(() => { if (!document.hidden) refresh(); }, 4000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
window.addEventListener('storage', event => {
  if (event.key === 'tunneldesk.access' && event.newValue) {
    token = event.newValue;
    refresh();
  }
});
