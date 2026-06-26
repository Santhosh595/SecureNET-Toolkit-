/**
 * SecureNET Control Panel - Core Application JS
 * Vanilla JS, no dependencies.
 */

// ─── Global App State ───────────────────────────────────────────────
const App = {
  statusPollingInterval: null,
  activityRefreshInterval: null,
  clockInterval: null,
  searchDebounceTimer: null,
  currentPage: 'dashboard',
  tools: {},
  alerts: [],
  activityFeed: [],
  lastToolStates: {},
};

// ─── API Helper ─────────────────────────────────────────────────────
async function api(endpoint, options = {}) {
  const defaults = {
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
    credentials: 'same-origin',
  };
  const config = { ...defaults, ...options };
  if (config.body && typeof config.body === 'object' && !(config.body instanceof FormData)) {
    config.body = JSON.stringify(config.body);
  }
  try {
    const res = await fetch(`/api${endpoint}`, config);
    if (!res.ok) {
      const text = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    const ct = res.headers.get('content-type') || '';
    return ct.includes('application/json') ? await res.json() : await res.text();
  } catch (err) {
    if (err.name === 'TypeError') throw new Error('Network unreachable');
    throw err;
  }
}

// ─── Status Polling (5s) ───────────────────────────────────────────
function startStatusPolling() {
  App.statusPollingInterval = setInterval(fetchStatus, 5000);
  fetchStatus(); // immediate first fetch
}

async function fetchStatus() {
  try {
    const data = await api('/status');
    updateToolCards(data.tools || {});
    App.tools = data.tools || {};
  } catch (err) {
    showToast('Status poll failed: ' + err.message, 'warning');  }
}

// ─── Tool Card Status Dots ─────────────────────────────────────────
// ponytail: single function drives all tool cards; extend states here
const TOOL_STATES = {
  running:  { dot: 'green',   label: 'Running' },
  stopped:  { dot: 'red',     label: 'Stopped' },
  warning:  { dot: 'yellow',  label: 'Warning' },
  unknown:  { dot: 'grey',    label: 'Unknown' },
};

function updateToolCards(tools) {
  Object.entries(tools).forEach(([name, info]) => {
    const card = document.querySelector(`[data-tool="${name}"]`);
    if (!card) return;
    const dot = card.querySelector('.status-dot');
    const label = card.querySelector('.status-label');
    const stateKey = info.status || 'unknown';
    const state = TOOL_STATES[stateKey] || TOOL_STATES.unknown;

    if (dot) {
      dot.classList.remove('dot-green', 'dot-red', 'dot-yellow', 'dot-grey');
      dot.classList.add(`dot-${state.dot}`);
      dot.title = state.label;
    }
    if (label) label.textContent = state.label;

    // Toggle action buttons based on state
    const startBtn = card.querySelector('[data-action="start"]');
    const stopBtn = card.querySelector('[data-action="stop"]');
    const restartBtn = card.querySelector('[data-action="restart"]');
    if (startBtn) startBtn.disabled = stateKey === 'running';
    if (stopBtn) stopBtn.disabled = stateKey === 'stopped';
    if (restartBtn) restartBtn.disabled = stateKey !== 'running';

    // Track state transitions for toast notifications
    const prev = App.lastToolStates[name];
    if (prev && prev !== stateKey) {
      showToast(`${name}: ${prev} → ${state.label}`, stateKey === 'running' ? 'success' : 'info');
    }
    App.lastToolStates[name] = stateKey;
  });
}

// ─── Toast Notification System (bottom-right) ───────────────────────
function showToast(message, type = 'info', duration = 4000) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;';
    document.body.appendChild(container);
  }

  const colors = {
    success: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
    info: '#3b82f6',
  };

  const toast = document.createElement('div');
  toast.style.cssText = `
    pointer-events:auto;
    padding:10px 16px;
    border-radius:6px;
    color:#fff;
    font-size:13px;
    background:${colors[type] || colors.info};
    box-shadow:0 4px 12px rgba(0,0,0,0.25);
    transform:translateX(120%);
    transition:transform 0.3s ease, opacity 0.3s ease;
    opacity:0;
    max-width:320px;
    word-wrap:break-word;
  `;
  toast.textContent = message;
  container.appendChild(toast);
  toast.offsetHeight; // trigger reflow
  toast.style.transform = 'translateX(0)';
  toast.style.opacity = '1';

  setTimeout(() => {
    toast.style.transform = 'translateX(120%)';
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ─── Modal Management ──────────────────────────────────────────────
function openModal(modalId) {
  const modal = document.getElementById(modalId);
  if (!modal) return;
  modal.classList.add('active');
  modal.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
  const firstInput = modal.querySelector('input, textarea, select, button:not(.modal-close)');
  if (firstInput) firstInput.focus();
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (!modal) return;
  modal.classList.remove('active');
  modal.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
}

function closeAllModals() {
  document.querySelectorAll('.modal.active').forEach(m => {
    m.classList.remove('active');
    m.setAttribute('aria-hidden', 'true');
  });
  document.body.style.overflow = '';
}

document.addEventListener('click', e => {
  if (e.target.matches('[data-modal-open]')) {
    e.preventDefault();
    openModal(e.target.dataset.modalOpen);
  }
  if (e.target.matches('[data-modal-close]') || e.target.classList.contains('modal-backdrop')) {
    e.preventDefault();
    closeAllModals();
  }
});

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeAllModals();
});

// ─── Keyboard Shortcuts ────────────────────────────────────────────
const KEYBOARD_TARGETS = {
  '1': 'dashboard', '2': 'tools', '3': 'alerts', '4': 'scan',
  '5': 'logs', '6': 'monitor', '7': 'settings', '8': 'users',
  '9': 'config', '0': 'help',
};

document.addEventListener('keydown', e => {
  // Let user type in inputs without hijacking modals
  const tag = document.activeElement?.tagName;
  const inField = tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';

  if (e.ctrlKey || e.metaKey) {
    if (inField) return;

    // Ctrl+1-0 → navigate to section
    if (KEYBOARD_TARGETS[e.key]) {
      e.preventDefault();
      navigateTo(KEYBOARD_TARGETS[e.key]);
      return;
    }
    // Ctrl+A → acknowledge all alerts
    if (e.key === 'a' && !e.shiftKey) {
      e.preventDefault();
      acknowledgeAllAlerts();
      return;
    }
    // Ctrl+Shift+A → admin panel
    if (e.key === 'A') {
      e.preventDefault();
      navigateTo('admin');
      return;
    }
    // Ctrl+H → show shortcuts help
    if (e.key === 'h') {
      e.preventDefault();
      openModal('keyboard-shortcuts-modal');
      return;
    }
    // Ctrl+S → focus search
    if (e.key === 's') {
      e.preventDefault();
      const searchInput = document.getElementById('global-search');
      if (searchInput) searchInput.focus();
      return;
    }
    // Ctrl+/ → search (browsers block this in some cases, but try)
    if (e.key === '/') {
      e.preventDefault();
      const searchInput = document.getElementById('global-search');
      if (searchInput) searchInput.focus();
      return;
    }
  }

  // ? (without Ctrl) → show shortcuts (when not in input)
  if (!inField && e.key === '?' && !e.ctrlKey && !e.metaKey) {
    e.preventDefault();
    openModal('keyboard-shortcuts-modal');
  }
});

// ─── Page Navigation / Transitions ──────────────────────────────────
function navigateTo(page) {
  document.querySelectorAll('[data-page]').forEach(el => {
    if (el.dataset.page === page) {
      el.classList.remove('page-hidden');
      el.classList.add('page-enter');
      requestAnimationFrame(() => el.classList.remove('page-enter'));
    } else {
      el.classList.add('page-hidden');
    }
  });
  document.querySelectorAll('[data-nav]').forEach(el => {
    el.classList.toggle('nav-active', el.dataset.nav === page);
  });
  App.currentPage = page;
}

// ─── Live Clock ─────────────────────────────────────────────────────
function startClock() {
  App.clockInterval = setInterval(() => {
    const el = document.getElementById('live-clock');
    if (el) el.textContent = new Date().toLocaleTimeString();
  }, 1000);
  // immediate
  const el = document.getElementById('live-clock');
  if (el) el.textContent = new Date().toLocaleTimeString();
}

// ─── Recent Activity Feed (10s) ────────────────────────────────────
function startActivityRefresh() {
  App.activityRefreshInterval = setInterval(refreshActivityFeed, 10000);
  refreshActivityFeed();
}

async function refreshActivityFeed() {
  try {
    const data = await api('/activity?limit=20');
    App.activityFeed = data.entries || data || [];
    renderActivityFeed();
  } catch (err) {
    // silent; next poll retries
  }
}

function renderActivityFeed() {
  const container = document.getElementById('activity-feed');
  if (!container) return;
  if (!App.activityFeed.length) {
    container.innerHTML = '<li class="activity-empty">No recent activity</li>';
    return;
  }
  container.innerHTML = App.activityFeed.map(entry => {
    const ts = entry.timestamp
      ? new Date(entry.timestamp).toLocaleTimeString()
      : '';
    const msg = entry.message || entry.text || JSON.stringify(entry).slice(0, 120);
    return `<li class="activity-item"><time>${ts}</time><span>${escapeHtml(msg)}</span></li>`;
  }).join('');
}

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[c]);
}

// ─── Quick Scan Form Handler ───────────────────────────────────────
function initQuickScan() {
  const form = document.getElementById('quick-scan-form');
  if (!form) return;
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const target = form.querySelector('#scan-target')?.value?.trim();
    if (!target) {
      showToast('Enter a target IP/hostname', 'warning');
      return;
    }
    const submitBtn = form.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Scanning...';
    try {
      const result = await api('/scan', { method: 'POST', body: { target } });
      showToast(result.message || `Scan of ${target} complete`, 'success');
      showToast(`Results: ${JSON.stringify(result).slice(0, 200)}`, 'info', 6000);
    } catch (err) {
      showToast('Scan failed: ' + err.message, 'error');
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = 'Start Scan';
    }
  });
}

// ─── Alert Acknowledge Handler ─────────────────────────────────────
async function acknowledgeAlert(alertId) {
  try {
    await api(`/alerts/${alertId}/acknowledge`, { method: 'POST' });
    const btn = document.querySelector(`[data-alert-ack="${alertId}"]`);
    if (btn) {
      btn.disabled = true;
      btn.textContent = '✓ Acknowledged';
      btn.classList.add('ack-confirmed');
    }
    showToast(`Alert #${alertId} acknowledged`, 'success');
  } catch (err) {
    showToast('Failed to acknowledge: ' + err.message, 'error');
  }
}

async function acknowledgeAllAlerts() {
  const pending = document.querySelectorAll('[data-alert-ack]:not(:disabled)');
  if (!pending.length) {
    showToast('No pending alerts', 'info');
    return;
  }
  try {
    await api('/alerts/acknowledge-all', { method: 'POST' });
    showToast('All alerts acknowledged', 'success');
    if (App.statusPollingInterval) fetchStatus();
  } catch (err) {
    showToast('Bulk ack failed: ' + err.message, 'error');
  }
}

// ─── Tool Start/Stop/Restart Handlers ──────────────────────────────
async function toolAction(toolName, action) {
  const labels = { start: 'Starting', stop: 'Stopping', restart: 'Restarting' };
  try {
    showToast(`${labels[action]} ${toolName}...`, 'info');
    await api(`/tools/${toolName}/${action}`, { method: 'POST' });
    showToast(`${toolName} ${action} command sent`, 'success');
    fetchStatus(); // poll immediately to update UI
  } catch (err) {
    showToast(`Failed to ${action} ${toolName}: ${err.message}`, 'error');
  }
}

// Delegated click handler for tool action buttons
document.addEventListener('click', e => {
  const btn = e.target.closest('[data-action]');
  if (!btn) return;
  const card = btn.closest('[data-tool]');
  if (!card) return;
  const tool = card.dataset.tool;
  const action = btn.dataset.action;
  if (tool && action) {
    e.preventDefault();
    toolAction(tool, action);
  }
  // ACK buttons
  const ackBtn = e.target.closest('[data-alert-ack]');
  if (ackBtn) {
    alertId = ackBtn.dataset.alertAck;
    if (alertId) acknowledgeAlert(alertId);
  }
});

// ─── Search / Filter Debouncing ────────────────────────────────────
function initSearch() {
  const input = document.getElementById('global-search');
  if (!input) return;
  input.addEventListener('input', () => {
    clearTimeout(App.searchDebounceTimer);
    App.searchDebounceTimer = setTimeout(() => performSearch(input.value), 300);
  });
}

function performSearch(query) {
  const q = query.toLowerCase().trim();
  document.querySelectorAll('[data-searchable]').forEach(el => {
    const text = (el.textContent || '').toLowerCase();
    const tags = (el.dataset.tags || '').toLowerCase();
    el.style.display = (!q || text.includes(q) || tags.includes(q)) ? '' : 'none';
  });
}

// ─── Page Transition Animations ────────────────────────────────────
// Applied via .page-enter class (calls fadeSlideIn keyframe).
// CSS fallback injected once so any page container gets the animation.
function injectPageTransitionStyles() {
  if (document.getElementById('page-transitions')) return;
  const style = document.createElement('style');
  style.id = 'page-transitions';
  style.textContent = `
    [data-page] { transition: opacity 0.25s ease, transform 0.25s ease; }
    .page-hidden { display: none !important; opacity: 0; transform: translateY(8px); }
    .page-enter { animation: fadeInSlideUp 0.25s ease forwards; }
    @keyframes fadeInSlideUp {
      from { opacity: 0; transform: translateY(12px); }
      to   { opacity: 1; transform: translateY(0); }
    }
  `;
  document.head.appendChild(style);
}

// ─── Boot ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  injectPageTransitionStyles();
  startClock();
  startStatusPolling();
  startActivityRefresh();
  initQuickScan();
  initSearch();
});

// Expose for inline onclick if needed
window.App = App;
window.showToast = showToast;
window.openModal = openModal;
window.closeModal = closeModal;
window.navigateTo = navigateTo;
window.toolAction = toolAction;
window.acknowledgeAlert = acknowledgeAlert;
