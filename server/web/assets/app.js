const state = {
  token: localStorage.getItem("af.managerToken") || "",
  lastConfigText: "",
  lastBatchesText: "",
  hosts: [],
  operationRecords: parseJson(localStorage.getItem("af.operationRecords") || "[]", []),
  actorIdentity: localStorage.getItem("af.actorIdentity") || "本地控制台用户",
  autoRefresh: localStorage.getItem("af.autoRefresh") !== "false",
  refreshInFlight: false,
  liveRefreshInFlight: false,
  lastRenderedHostsKey: "",
  currentUser: localStorage.getItem("af.currentUser") || "",
  collusionConfigLoaded: false,   // 合谋检测配置/规则/工单仅在首次进入时拉取，避免覆盖编辑中内容
};

const $ = (id) => document.getElementById(id);

const els = {
  loginView: $("loginView"),
  appShell: $("appShell"),
  loginForm: $("loginForm"),
  loginUsername: $("loginUsername"),
  loginPassword: $("loginPassword"),
  loginMessage: $("loginMessage"),
  loginSubmitBtn: $("loginSubmitBtn"),
  endpointText: $("endpointText"),
  autoRefreshToggle: $("autoRefreshToggle"),
  refreshBtn: $("refreshBtn"),
  tokenBtn: $("tokenBtn"),
  viewBackBtn: $("viewBackBtn"),
  currentViewTitle: $("currentViewTitle"),
  notice: $("notice"),
  statusPill: $("statusPill"),
  eventsCollected: $("eventsCollected"),
  eventsUploaded: $("eventsUploaded"),
  eventsFailed: $("eventsFailed"),
  alerts: $("alerts"),
  uptime: $("uptime"),
  eventsDropped: $("eventsDropped"),
  bytesUploaded: $("bytesUploaded"),
  lastUpdated: $("lastUpdated"),
  configView: $("configView"),
  reloadConfigBtn: $("reloadConfigBtn"),
  copyConfigBtn: $("copyConfigBtn"),
  batchList: $("batchList"),
  batchCount: $("batchCount"),
  hostList: $("hostList"),
  hostCount: $("hostCount"),
  hostSearch: $("hostSearch"),
  hostStatusFilter: $("hostStatusFilter"),
  hostHistoryTitle: $("hostHistoryTitle"),
  hostHistoryOutput: $("hostHistoryOutput"),
  refreshSecurityBtn: $("refreshSecurityBtn"),
  securitySummary: $("securitySummary"),
  alertList: $("alertList"),
  operationLogList: $("operationLogList"),
  analyticsLogCount: $("analyticsLogCount"),
  analyticsAlertCount: $("analyticsAlertCount"),
  operationTypeBreakdown: $("operationTypeBreakdown"),
  alertSeverityBreakdown: $("alertSeverityBreakdown"),
  logCollectorFilter: $("logCollectorFilter"),
  logPriorityFilter: $("logPriorityFilter"),
  refreshLogPolicyBtn: $("refreshLogPolicyBtn"),
  logPolicySummary: $("logPolicySummary"),
  logPolicyHost: $("logPolicyHost"),
  logPolicyQueryBtn: $("logPolicyQueryBtn"),
  collectorCounts: $("collectorCounts"),
  collectorCountsDetail: $("collectorCountsDetail"),
  latencyHighAvg: $("latencyHighAvg"),
  latencyHighCount: $("latencyHighCount"),
  latencyNormalAvg: $("latencyNormalAvg"),
  latencyNormalCount: $("latencyNormalCount"),
  latencyRatio: $("latencyRatio"),
  latencyTarget: $("latencyTarget"),
  latencyP95: $("latencyP95"),
  filterProfileRows: $("filterProfileRows"),
  addFilterProfileBtn: $("addFilterProfileBtn"),
  saveFilterProfilesBtn: $("saveFilterProfilesBtn"),
  filterProfileMsg: $("filterProfileMsg"),
  hostId: $("hostId"),
  hostName: $("hostName"),
  hostIp: $("hostIp"),
  hostHardware: $("hostHardware"),
  hostOs: $("hostOs"),
  hostPermissions: $("hostPermissions"),
  hostNote: $("hostNote"),
  saveHostBtn: $("saveHostBtn"),
  resetHostFormBtn: $("resetHostFormBtn"),
  remoteHostId: $("remoteHostId"),
  remoteCommandType: $("remoteCommandType"),
  remotePayload: $("remotePayload"),
  sendRemoteCommandBtn: $("sendRemoteCommandBtn"),
  actorIdentity: $("actorIdentity"),
  operationRecordList: $("operationRecordList"),
  operationRecordJson: $("operationRecordJson"),
  recordCount: $("recordCount"),
  copyRecordsBtn: $("copyRecordsBtn"),
  exportRecordsBtn: $("exportRecordsBtn"),
  clearRecordsBtn: $("clearRecordsBtn"),
  upgradeUrl: $("upgradeUrl"),
  upgradeBtn: $("upgradeBtn"),
  tokenDialog: $("tokenDialog"),
  tokenInput: $("tokenInput"),
  clearTokenBtn: $("clearTokenBtn"),
  cancelTokenBtn: $("cancelTokenBtn"),
  saveTokenBtn: $("saveTokenBtn"),
  // 合谋检测面板
  refreshCollusionBtn: $("refreshCollusionBtn"),
  collusionSummary: $("collusionSummary"),
  collusionHighCount: $("collusionHighCount"),
  collusionMidCount: $("collusionMidCount"),
  collusionLowCount: $("collusionLowCount"),
  collusionPendingCount: $("collusionPendingCount"),
  collusionEmergencyBtn: $("collusionEmergencyBtn"),
  collusionEnabled: $("collusionEnabled"),
  collusionWindows: $("collusionWindows"),
  collusionThresholds: $("collusionThresholds"),
  collusionRuleStats: $("collusionRuleStats"),
  collusionProfileStats: $("collusionProfileStats"),
  collusionEmergency: $("collusionEmergency"),
  collusionLevelFilter: $("collusionLevelFilter"),
  collusionStatusFilter: $("collusionStatusFilter"),
  collusionEventList: $("collusionEventList"),
  collusionReportDays: $("collusionReportDays"),
  collusionReportBtn: $("collusionReportBtn"),
  collusionReportView: $("collusionReportView"),
  collusionConfigText: $("collusionConfigText"),
  collusionRulesText: $("collusionRulesText"),
  collusionWorkordersText: $("collusionWorkordersText"),
  saveCollusionConfigBtn: $("saveCollusionConfigBtn"),
  saveCollusionRulesBtn: $("saveCollusionRulesBtn"),
  saveCollusionWorkordersBtn: $("saveCollusionWorkordersBtn"),
  // 连接请求与数据库管理
  refreshConnectionsBtn: $("refreshConnectionsBtn"),
  connectionCount: $("connectionCount"),
  connectionList: $("connectionList"),
  refreshDbHostsBtn: $("refreshDbHostsBtn"),
  dbHostSelect: $("dbHostSelect"),
  dbTableSelect: $("dbTableSelect"),
  dbSearch: $("dbSearch"),
  dbLimit: $("dbLimit"),
  dbQueryBtn: $("dbQueryBtn"),
  dbExportBtn: $("dbExportBtn"),
  dbResultInfo: $("dbResultInfo"),
  dbResultHead: $("dbResultHead"),
  dbResultBody: $("dbResultBody"),
  dbPagination: $("dbPagination"),
  dbPrevPage: $("dbPrevPage"),
  dbNextPage: $("dbNextPage"),
  dbPageInfo: $("dbPageInfo"),
  // 操作员台账（M5-4）
  refreshOperatorsBtn: $("refreshOperatorsBtn"),
  operatorCount: $("operatorCount"),
  operatorSearch: $("operatorSearch"),
  operatorStatusFilter: $("operatorStatusFilter"),
  operatorTotal: $("operatorTotal"),
  operatorOnline: $("operatorOnline"),
  operatorBound: $("operatorBound"),
  operatorUnbound: $("operatorUnbound"),
  operatorId: $("operatorId"),
  operatorName: $("operatorName"),
  operatorHostSelect: $("operatorHostSelect"),
  operatorStatus: $("operatorStatus"),
  saveOperatorBtn: $("saveOperatorBtn"),
  resetOperatorFormBtn: $("resetOperatorFormBtn"),
  operatorStoragePath: $("operatorStoragePath"),
  operatorList: $("operatorList"),
  operatorBindingSummary: $("operatorBindingSummary"),
  operatorBindingList: $("operatorBindingList"),
};

const validationRules = {
  hostId: { label: "主机 ID", pattern: /^[A-Za-z0-9_-]{2,64}$/, optional: true, message: "主机 ID 只能包含字母、数字、短横线和下划线，长度为 2 到 64 个字符。" },
  hostName: { label: "主机名称", required: true, min: 1, max: 80 },
  hostIp: { label: "IP 地址", format: "ipv4", optional: true, message: "IP 地址格式不正确，例如 192.168.1.10。" },
  hostHardware: { label: "硬件配置", max: 120, optional: true },
  hostOs: { label: "操作系统版本", max: 120, optional: true },
  hostPermissions: { label: "远控权限", format: "permissionList", maxItems: 20, optional: true },
  hostNote: { label: "备注", max: 240, optional: true },
  remoteHostId: { label: "目标主机 ID", required: true, pattern: /^[A-Za-z0-9_-]{2,64}$/, message: "目标主机 ID 格式不正确。" },
  remotePayload: { label: "指令参数", max: 2048, optional: true },
  upgradeUrl: { label: "升级包 URL", required: true, format: "httpUrl", max: 2048 },
  tokenInput: { label: "管理 Token", max: 256, optional: true },
  loginUsername: { label: "账号", required: true, min: 2, max: 64, pattern: /^[A-Za-z0-9_.@-]+$/, message: "账号只能包含字母、数字、点、下划线、短横线或 @。" },
  loginPassword: { label: "密码", required: true, min: 6, max: 128 },
  operatorId: { label: "操作员 ID", required: true, pattern: /^[A-Za-z0-9_-]{2,64}$/, message: "操作员 ID 只能包含字母、数字、短横线和下划线，长度为 2 到 64 个字符。" },
  operatorName: { label: "显示名", max: 80, optional: true },
};

function authHeaders(extra = {}) {
  const headers = { ...extra };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  return headers;
}

function showLogin(message = "") {
  if (els.loginView) els.loginView.classList.remove("hidden");
  if (els.appShell) els.appShell.classList.add("hidden");
  if (message && els.loginMessage) {
    els.loginMessage.textContent = message;
    els.loginMessage.className = "login-message";
  }
}

function showApp() {
  if (els.loginView) els.loginView.classList.add("hidden");
  if (els.appShell) els.appShell.classList.remove("hidden");
}

// 纯 JS SHA-256 降级实现（Web Crypto 不可用时使用，如 HTTP 非 localhost 环境）
function sha256HexFallback(text) {
  function rotr(n, x) { return (x >>> n) | (x << (32 - n)); }
  const K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  const bytes = new TextEncoder().encode(text);
  const bitLen = bytes.length * 8;
  // 填充：0x80 + 0x00... + 64位长度
  const padLen = (56 - (bytes.length + 1) % 64 + 64) % 64;
  const totalLen = bytes.length + 1 + padLen + 8;
  const buf = new Uint8Array(totalLen);
  buf.set(bytes, 0);
  buf[bytes.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(totalLen - 4, bitLen >>> 0, false);
  dv.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000), false);

  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
  let h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;

  for (let off = 0; off < totalLen; off += 64) {
    const W = new Uint32Array(64);
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(7, W[i-15]) ^ rotr(18, W[i-15]) ^ (W[i-15] >>> 3);
      const s1 = rotr(17, W[i-2]) ^ rotr(19, W[i-2]) ^ (W[i-2] >>> 10);
      W[i] = (W[i-16] + s0 + W[i-7] + s1) | 0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(6,e) ^ rotr(11,e) ^ rotr(25,e);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + W[i]) | 0;
      const S0 = rotr(2,a) ^ rotr(13,a) ^ rotr(22,a);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) | 0;
      h=g; g=f; f=e; e=(d + t1) | 0; d=c; c=b; b=a; a=(t1 + t2) | 0;
    }
    h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0;
    h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
  }
  const out = [h0,h1,h2,h3,h4,h5,h6,h7];
  return out.map((v) => (v >>> 0).toString(16).padStart(8, "0")).join("");
}

async function sha256Hex(text) {
  if (window.crypto?.subtle) {
    try {
      const bytes = new TextEncoder().encode(text);
      const digest = await window.crypto.subtle.digest("SHA-256", bytes);
      return [...new Uint8Array(digest)].map((item) => item.toString(16).padStart(2, "0")).join("");
    } catch (e) {
      // Web Crypto 调用失败时降级到纯 JS 实现
    }
  }
  return sha256HexFallback(text);
}

function setLoginMessage(message, type = "error") {
  if (!els.loginMessage) return;
  els.loginMessage.textContent = message;
  els.loginMessage.className = `login-message ${type === "success" ? "success" : ""}`;
}

async function login(event) {
  event.preventDefault();
  const errors = validateFields(["loginUsername", "loginPassword"]);
  if (errors.length) {
    setLoginMessage(errors[0]);
    return;
  }
  const stopLoading = setLoading(els.loginSubmitBtn, "登录中...");
  try {
    const username = els.loginUsername.value.trim();
    const passwordSha256 = await sha256Hex(els.loginPassword.value);
    const response = await fetch("/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password_sha256: passwordSha256 }),
    });
    const text = await response.text();
    const data = parseJson(text, {});
    if (!response.ok) {
      throw new Error(data.message || "账号或密码不正确。");
    }
    state.token = data.token || "";
    state.currentUser = data.username || username;
    localStorage.setItem("af.managerToken", state.token);
    localStorage.setItem("af.currentUser", state.currentUser);
    els.loginPassword.value = "";
    setLoginMessage("登录成功，正在进入控制台。", "success");
    showApp();
    renderView(routerState.current);
    refreshAll({ record: false });
  } catch (err) {
    setLoginMessage(err.message || "账号或密码不正确。");
  } finally {
    stopLoading();
  }
}

function showNotice(message, type = "success") {
  els.notice.textContent = message;
  els.notice.className = `notice ${type}`;
  window.clearTimeout(showNotice.timer);
  showNotice.timer = window.setTimeout(() => {
    els.notice.className = "notice hidden";
  }, 4200);
}

function timestampSeconds(date = new Date()) {
  return new Date(Math.floor(date.getTime() / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

function formatLocalTime(isoString) {
  if (!isoString) return "--";
  try {
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return isoString;
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  } catch (e) {
    return isoString;
  }
}

function currentActor() {
  const identity = (els.actorIdentity?.value || state.actorIdentity || "本地控制台用户").trim();
  return {
    identity,
    source: "web_console",
    endpoint: window.location.host || "local",
    user_agent: navigator.userAgent,
  };
}

function persistOperationRecords() {
  localStorage.setItem("af.operationRecords", JSON.stringify(state.operationRecords));
}

function recordOperation({ object, type, details, status, error }) {
  const record = {
    actor: currentActor(),
    timestamp: timestampSeconds(),
    object: object || "未指定对象",
    operation_type: type || "unknown",
    operation_details: details || "",
    status: status || (error ? "failure" : "success"),
  };
  if (error) record.error_message = String(error.message || error);
  state.operationRecords.unshift(record);
  state.operationRecords = state.operationRecords.slice(0, 200);
  persistOperationRecords();
  renderOperationRecords();
  return record;
}

function renderOperationRecords() {
  const records = Array.isArray(state.operationRecords) ? state.operationRecords : [];
  els.recordCount.textContent = `${records.length} 条记录`;
  els.operationRecordJson.textContent = JSON.stringify(records, null, 2);
  if (records.length === 0) {
    els.operationRecordList.innerHTML = `
      <tr>
        <td colspan="6" class="empty-cell">暂无结构化操作记录。执行刷新、主机维护、日志查看、配置重载或升级请求后会自动生成。</td>
      </tr>
    `;
    return;
  }
  els.operationRecordList.innerHTML = records.map((record) => `
    <tr>
      <td>${escapeHtml(formatLocalTime(record.timestamp))}</td>
      <td>${escapeHtml(record.actor?.identity || "--")}</td>
      <td>${escapeHtml(record.object)}</td>
      <td><code>${escapeHtml(record.operation_type)}</code></td>
      <td>${escapeHtml(record.operation_details)}</td>
      <td><span class="status-tag ${record.status === "success" ? "success" : "failure"}">${record.status === "success" ? "成功" : "失败"}</span></td>
    </tr>
  `).join("");
}

async function copyOperationRecords() {
  const text = JSON.stringify(state.operationRecords, null, 2);
  try {
    await navigator.clipboard.writeText(text);
    showNotice("结构化操作记录已复制。");
    recordOperation({
      object: "结构化操作记录",
      type: "copy_operation_records",
      details: `复制 ${state.operationRecords.length} 条操作记录`,
      status: "success",
    });
  } catch (err) {
    showNotice("当前浏览器不允许自动复制，请手动选择复制。", "error");
    recordOperation({
      object: "结构化操作记录",
      type: "copy_operation_records",
      details: "复制结构化操作记录失败",
      status: "failure",
      error: err,
    });
  }
}

function exportOperationRecords() {
  const text = JSON.stringify(state.operationRecords, null, 2);
  const blob = new Blob([text], { type: "application/json;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `auditforwarder-operation-records-${timestampSeconds().replaceAll(":", "-")}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(link.href);
  showNotice("结构化操作记录已导出。");
  recordOperation({
    object: "结构化操作记录",
    type: "export_operation_records",
    details: `导出 ${state.operationRecords.length} 条操作记录为 JSON 文件`,
    status: "success",
  });
}

function clearOperationRecords() {
  const removed = state.operationRecords.length;
  state.operationRecords = [];
  persistOperationRecords();
  renderOperationRecords();
  showNotice(`结构化操作记录已清空，共移除 ${removed} 条。`);
}

function setLoading(button, loadingText) {
  if (!button) return () => {};
  const original = button.textContent;
  button.disabled = true;
  button.textContent = loadingText;
  return () => {
    button.disabled = false;
    button.textContent = original;
  };
}

async function request(path, options = {}) {
  const timeoutMs = options.timeoutMs || 10000;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(path, {
      ...options,
      signal: controller.signal,
      credentials: "same-origin",
      headers: authHeaders(options.headers || {}),
    }).catch((err) => {
      if (err.name === "AbortError") throw new Error(`接口请求超时：${path}`);
      throw err;
    });
    const text = await response.text();
    if (!response.ok) {
      const data = parseJson(text, null);
      if (data && Array.isArray(data.validation_errors)) {
        throw new Error(data.validation_errors.map((item) => `${item.field}: ${item.message}`).join("；"));
      }
      if (response.status === 401) {
        state.token = "";
        localStorage.removeItem("af.managerToken");
        showLogin("登录已失效，请重新输入账号和密码。");
      }
      const message = response.status === 401
        ? "接口未授权，请重新登录。"
        : `接口请求失败：HTTP ${response.status}`;
      throw new Error(`${message}${text ? ` ${text}` : ""}`);
    }
    return text;
  } finally {
    window.clearTimeout(timer);
  }
}

function ensureValidationNode(input) {
  if (!input) return null;
  const field = input.closest(".field") || input.parentElement;
  if (!field) return null;
  let node = field.querySelector(".field-feedback");
  if (!node) {
    node = document.createElement("small");
    node.className = "field-feedback";
    field.appendChild(node);
  }
  return node;
}

function validateValue(value, rule) {
  const text = String(value ?? "").trim();
  if (rule.required && !text) return `${rule.label}不能为空。`;
  if (!text && rule.optional) return "";
  if (rule.min && text.length < rule.min) return `${rule.label}长度不能少于 ${rule.min} 个字符。`;
  if (rule.max && text.length > rule.max) return `${rule.label}长度不能超过 ${rule.max} 个字符。`;
  if (rule.pattern && !rule.pattern.test(text)) return rule.message || `${rule.label}格式不正确。`;
  if (rule.format === "ipv4" && text && !/^((25[0-5]|2[0-4]\d|1?\d?\d)(\.|$)){4}$/.test(text)) {
    return rule.message || `${rule.label}格式不正确。`;
  }
  if (rule.format === "httpUrl" && text && !/^https?:\/\/\S+$/i.test(text)) {
    return `${rule.label}必须以 http:// 或 https:// 开头。`;
  }
  if (rule.format === "permissionList" && text) {
    const items = permissionList(text);
    if (items.length > (rule.maxItems || 20)) return `${rule.label}不能超过 ${rule.maxItems || 20} 项。`;
    if (items.some((item) => !/^[A-Za-z0-9_*-]+$/.test(item))) {
      return `${rule.label}只能包含字母、数字、下划线、短横线或 *，多项用逗号分隔。`;
    }
  }
  if (rule.minValue !== undefined || rule.maxValue !== undefined) {
    const number = Number(text);
    if (!Number.isFinite(number)) return `${rule.label}必须是数字。`;
    if (rule.minValue !== undefined && number < rule.minValue) return `${rule.label}不能小于 ${rule.minValue}。`;
    if (rule.maxValue !== undefined && number > rule.maxValue) return `${rule.label}不能大于 ${rule.maxValue}。`;
  }
  return "";
}

function setFieldValidation(input, message) {
  if (!input) return;
  const node = ensureValidationNode(input);
  input.classList.toggle("invalid", Boolean(message));
  input.classList.toggle("valid", !message && String(input.value || "").trim().length > 0);
  if (node) {
    node.textContent = message || "格式正确";
    node.className = `field-feedback ${message ? "error" : "success"}`;
  }
}

function validateField(input, rule) {
  const message = validateValue(input?.value, rule);
  setFieldValidation(input, message);
  return message;
}

function validateFields(fieldIds) {
  const errors = [];
  for (const id of fieldIds) {
    const rule = validationRules[id];
    const input = els[id];
    if (!rule || !input) continue;
    const message = validateField(input, rule);
    if (message) errors.push(message);
  }
  if (errors.length > 0) {
    showNotice(errors[0], "error");
    const firstId = fieldIds.find((id) => validateValue(els[id]?.value, validationRules[id]));
    if (firstId && els[firstId]) els[firstId].focus();
    return false;
  }
  return true;
}

function bindValidation() {
  Object.entries(validationRules).forEach(([id, rule]) => {
    const input = els[id];
    if (!input) return;
    ensureValidationNode(input);
    input.addEventListener("input", () => validateField(input, rule));
    input.addEventListener("blur", () => validateField(input, rule));
  });
}

function parseJson(text, fallback) {
  try {
    return JSON.parse(text);
  } catch (err) {
    return fallback;
  }
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("zh-CN");
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

function formatUptime(seconds) {
  const total = Number(seconds || 0);
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days > 0) return `${days} 天 ${hours} 小时`;
  if (hours > 0) return `${hours} 小时 ${minutes} 分钟`;
  return `${minutes} 分钟`;
}

function renderStatus(data) {
  const running = Boolean(data.running);
  els.statusPill.textContent = running ? "运行中" : "未运行";
  els.statusPill.className = `pill ${running ? "running" : "stopped"}`;
  els.eventsCollected.textContent = formatNumber(data.events_collected);
  els.eventsUploaded.textContent = formatNumber(data.events_uploaded);
  els.eventsFailed.textContent = formatNumber(data.events_failed);
  els.alerts.textContent = formatNumber(data.alerts);
  els.uptime.textContent = formatUptime(data.uptime_seconds);
  els.eventsDropped.textContent = formatNumber(data.events_dropped);
  els.bytesUploaded.textContent = formatBytes(data.bytes_uploaded);
  els.lastUpdated.textContent = new Date().toLocaleString("zh-CN");
}

function renderConfig(text) {
  const data = parseJson(text, null);
  state.lastConfigText = data ? JSON.stringify(data, null, 2) : text;
  els.configView.textContent = state.lastConfigText || "暂无配置数据";
}

function renderBatches(data) {
  const batches = Array.isArray(data.batches) ? data.batches : [];
  state.lastBatchesText = JSON.stringify({ batches }, null, 2);
  els.batchCount.textContent = `${batches.length} 个批次`;
  if (batches.length === 0) {
    els.batchList.innerHTML = `
      <div class="empty-state">
        <strong>暂无证据批次</strong>
        <p>当前还没有生成证据批次。采集到足够事件后，链模块会自动打包并在这里展示。</p>
      </div>
    `;
    return;
  }
  els.batchList.innerHTML = batches.map((batch, index) => `
    <article class="batch-item">
      <div class="batch-title">
        <div>
          <span class="batch-index">批次 ${String(index + 1).padStart(2, "0")}</span>
          <strong class="batch-id">${escapeHtml(batch.id || "未命名")}</strong>
        </div>
        <span class="batch-badge ${batch.signature ? "signed" : "unsigned"}">
          ${batch.signature ? "已签名" : "未签名"}
        </span>
      </div>

      <div class="batch-summary">
        <div class="summary-cell">
          <span>批次 ID</span>
          <strong>${escapeHtml(shortHash(batch.id))}</strong>
        </div>
        <div class="summary-cell">
          <span>Merkle Root 摘要</span>
          <strong>${escapeHtml(shortHash(batch.merkle_root))}</strong>
        </div>
        <div class="summary-cell">
          <span>签名摘要</span>
          <strong>${escapeHtml(shortHash(batch.signature))}</strong>
        </div>
      </div>

      <div class="batch-details">
        <div class="hash-row">
          <span>Merkle Root</span>
          <code>${escapeHtml(batch.merkle_root || "--")}</code>
        </div>
        <div class="hash-row">
          <span>数字签名</span>
          <code>${escapeHtml(batch.signature || "--")}</code>
        </div>
      </div>
    </article>
  `).join("");
}

function permissionList(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function debounce(fn, delay = 180) {
  let timer = 0;
  return (...args) => {
    window.clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), delay);
  };
}

function filteredHosts(hosts) {
  const keyword = String(els.hostSearch?.value || "").trim().toLowerCase();
  const status = els.hostStatusFilter?.value || "all";
  return hosts.filter((host) => {
    if (status === "online" && !host.online) return false;
    if (status === "offline" && host.online) return false;
    if (!keyword) return true;
    const haystack = [
      host.id,
      host.name,
      host.ip_address,
      host.os_version,
      host.hardware,
      host.network_status,
      host.note,
      ...(host.permissions || []),
    ].filter(Boolean).join(" ").toLowerCase();
    return haystack.includes(keyword);
  });
}

function renderHosts(data) {
  const hosts = Array.isArray(data.hosts) ? data.hosts : state.hosts;
  if (Array.isArray(data.hosts)) state.hosts = hosts;
  const visibleHosts = filteredHosts(hosts);
  const onlineCount = hosts.filter((host) => host.online).length;
  els.hostCount.textContent = visibleHosts.length === hosts.length
    ? `${hosts.length} 台主机，${onlineCount} 台在线`
    : `显示 ${visibleHosts.length} / ${hosts.length} 台主机，${onlineCount} 台在线`;
  const renderKey = JSON.stringify({
    hosts: visibleHosts,
    keyword: els.hostSearch?.value || "",
    status: els.hostStatusFilter?.value || "all",
  });
  if (renderKey === state.lastRenderedHostsKey) return;
  state.lastRenderedHostsKey = renderKey;
  if (hosts.length === 0) {
    els.hostList.innerHTML = `
      <div class="empty-state">
        <strong>暂无主机信息</strong>
        <p>请先添加主机，或让远端代理通过 <code>/hosts/heartbeat</code> 上报心跳。</p>
      </div>
    `;
    return;
  }
  if (visibleHosts.length === 0) {
    els.hostList.innerHTML = `
      <div class="empty-state">
        <strong>没有匹配的主机</strong>
        <p>请调整搜索关键字或在线状态筛选条件。</p>
      </div>
    `;
    return;
  }
  els.hostList.innerHTML = visibleHosts.map((host) => `
    <article class="host-card">
      <div class="host-card-head">
        <div>
          <span class="batch-index">${escapeHtml(host.online ? "在线" : "离线")}</span>
          <strong class="batch-id">${escapeHtml(host.name || host.id || "未命名主机")}</strong>
          <code>${escapeHtml(host.id || "--")}</code>
        </div>
        <span class="pill ${host.online ? "running" : "stopped"}">${host.online ? "在线" : "离线"}</span>
      </div>
      <div class="host-grid">
        <div><span>IP 地址</span><strong>${escapeHtml(host.ip_address || "--")}</strong></div>
        <div><span>操作系统</span><strong>${escapeHtml(host.os_version || "--")}</strong></div>
        <div><span>硬件配置</span><strong>${escapeHtml(host.hardware || "--")}</strong></div>
        <div><span>网络状态</span><strong>${escapeHtml(host.network_status || "--")}</strong></div>
        <div><span>CPU</span><strong>${formatNumber(host.cpu_usage_percent)}%</strong></div>
        <div><span>内存</span><strong>${formatNumber(host.memory_usage_percent)}%</strong></div>
        <div><span>最后心跳</span><strong>${escapeHtml(formatLocalTime(host.last_seen))}</strong></div>
        <div><span>权限</span><strong>${escapeHtml((host.permissions || []).join(", ") || "--")}</strong></div>
      </div>
      ${host.note ? `<p class="host-note">${escapeHtml(host.note)}</p>` : ""}
      <div class="section-actions">
        <button class="button ghost small" data-host-action="edit" data-host-id="${escapeHtml(host.id)}">编辑</button>
        <button class="button ghost small" data-host-action="select" data-host-id="${escapeHtml(host.id)}">设为远控目标</button>
        <button class="button ghost small" data-host-action="history-metrics" data-host-id="${escapeHtml(host.id)}">资源历史</button>
        <button class="button ghost small" data-host-action="history-audit" data-host-id="${escapeHtml(host.id)}">审计摘要</button>
        <button class="button ghost small" data-host-action="history-commands" data-host-id="${escapeHtml(host.id)}">命令结果</button>
        <button class="button ghost small" data-host-action="history-logs" data-host-id="${escapeHtml(host.id)}">操作日志</button>
        <button class="button ghost small" data-host-action="history-alerts" data-host-id="${escapeHtml(host.id)}">告警历史</button>
        <button class="button danger small" data-host-action="delete" data-host-id="${escapeHtml(host.id)}">删除</button>
      </div>
    </article>
  `).join("");
}

function parseJsonlLines(jsonl, limit = 10) {
  return String(jsonl || "")
    .split(/\r?\n/)
    .filter(Boolean)
    .slice(-limit)
    .reverse()
    .map((line) => parseJson(line, { raw: line }));
}

function renderSecurityItems(container, items, emptyText, type) {
  if (!container) return;
  if (!items.length) {
    container.innerHTML = `<div class="empty-state"><strong>${escapeHtml(emptyText)}</strong></div>`;
    return;
  }
  container.innerHTML = items.map((item) => {
    const severity = item.severity || "info";
    const title = item.message || item.operation_type || item.event_type || item.rule_id || "未命名记录";
    const meta = [
      formatLocalTime(item.timestamp),
      item.host_id,
      item.rule_id,
      item.operation_type || item.event_type,
      item.status,
    ].filter(Boolean).join(" · ");
    const details = item.evidence || item.command || item.operation_details || item.raw || "";
    return `
      <article class="security-item ${type === "alert" ? severity : ""}">
        <div class="security-item-head">
          <strong>${escapeHtml(title)}</strong>
          ${type === "alert" ? `<span class="severity ${escapeHtml(severity)}">${escapeHtml(severity)}</span>` : ""}
        </div>
        <p>${escapeHtml(meta || "--")}</p>
        ${details ? `<code>${escapeHtml(shortHash(details))}</code>` : ""}
      </article>
    `;
  }).join("");
}

function renderBreakdown(container, counts, emptyText) {
  if (!container) return;
  const entries = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    container.innerHTML = `<span class="muted">${escapeHtml(emptyText)}</span>`;
    return;
  }
  const max = Math.max(...entries.map((item) => Number(item[1]) || 0), 1);
  container.innerHTML = entries.map(([name, value]) => {
    const width = Math.max(6, Math.round(((Number(value) || 0) / max) * 100));
    return `
      <div class="breakdown-row">
        <span>${escapeHtml(name)}</span>
        <div class="breakdown-bar"><i style="width:${width}%"></i></div>
        <strong>${formatNumber(value)}</strong>
      </div>
    `;
  }).join("");
}

function renderSecurityAnalytics(data) {
  if (els.analyticsLogCount) els.analyticsLogCount.textContent = formatNumber(data.log_count || 0);
  if (els.analyticsAlertCount) els.analyticsAlertCount.textContent = formatNumber(data.alert_count || 0);
  renderBreakdown(els.operationTypeBreakdown, data.operation_types, "暂无操作类型统计");
  renderBreakdown(els.alertSeverityBreakdown, data.alert_severities, "暂无告警级别统计");
}

function logQueryParams(limit = 20) {
  const params = new URLSearchParams({ limit: String(limit) });
  const collector = els.logCollectorFilter ? els.logCollectorFilter.value : "";
  const priority = els.logPriorityFilter ? els.logPriorityFilter.value : "";
  if (collector) params.set("collector", collector);
  if (priority) params.set("priority", priority);
  return params.toString();
}

async function loadSecurityMonitor(options = {}) {
  if (!els.alertList || !els.operationLogList) return;
  try {
    const [alertsText, logsText, analyticsText] = await Promise.all([
      request("/alerts?limit=20"),
      request(`/logs/query?${logQueryParams(20)}`),
      request(`/logs/analytics?${logQueryParams(1000)}`),
    ]);
    const alerts = parseJson(alertsText, {});
    const logs = parseJson(logsText, {});
    const analytics = parseJson(analyticsText, {});
    const alertItems = parseJsonlLines(alerts.jsonl, 20);
    const logItems = parseJsonlLines(logs.jsonl, 20);
    renderSecurityItems(els.alertList, alertItems, "暂无违规告警", "alert");
    renderSecurityItems(els.operationLogList, logItems, "暂无操作日志", "log");
    renderSecurityAnalytics(analytics);
    els.securitySummary.textContent = `${alertItems.length} 条告警，${logItems.length} 条日志`;
  } catch (err) {
    els.securitySummary.textContent = "加载失败";
    renderSecurityItems(els.alertList, [], "告警加载失败", "alert");
    renderSecurityItems(els.operationLogList, [], "日志加载失败", "log");
    if (!options.silent) showNotice(err.message, "error");
  }
}

// ---------------- 跨操作员合谋协同检测面板 ----------------

function renderCollusionOverview(o) {
  const counts = o.event_counts || {};
  els.collusionHighCount.textContent = String(counts.HIGH ?? 0);
  els.collusionMidCount.textContent = String(counts.MID ?? 0);
  els.collusionLowCount.textContent = String(counts.LOW ?? 0);
  els.collusionPendingCount.textContent = String(o.pending_review ?? 0);
  els.collusionEnabled.textContent = o.started
    ? (o.enabled ? "运行中" : "已停用（配置 enabled=false）")
    : "未启动";
  els.collusionWindows.textContent = `${o.short_window_minutes ?? "--"} 分钟 / ${o.long_window_hours ?? "--"} 小时`;
  els.collusionThresholds.textContent = `中风险 ≥ ${o.score_mid ?? "--"} 分，高风险 ≥ ${o.score_high ?? "--"} 分`;
  els.collusionRuleStats.textContent = `${o.rules_count ?? "--"} 条规则 / ${o.asset_groups_count ?? "--"} 组资产`;
  els.collusionProfileStats.textContent = `${o.profile_operators ?? 0} 人 / ${o.profile_pairs ?? 0} 对协作`;
  els.collusionEmergency.textContent = o.emergency_mode ? "生效中（风险等级自动降一级）" : "未启用";
  els.collusionEmergencyBtn.textContent = o.emergency_mode ? "解除应急模式" : "开启应急模式";
}

function renderCollusionEvents(items) {
  if (!Array.isArray(items) || items.length === 0) {
    els.collusionEventList.innerHTML = `<div class="empty-cell">当前过滤条件下暂无风险事件。</div>`;
    return;
  }
  const levelClass = { HIGH: "high", MID: "medium", LOW: "" };
  els.collusionEventList.innerHTML = items.map((ev) => {
    const dispose = ev.dispose || {};
    const rules = (ev.matched_rules || []).join("、") || "仅行为画像线索（规则零命中）";
    const ops = (ev.operators || []).join("、");
    const notes = [...(ev.profile_notes || []), ...(ev.score_notes || [])].filter(Boolean).join("；");
    return `
      <div class="security-item ${levelClass[ev.risk_level] || ""}" data-event-id="${escapeHtml(ev.event_id || "")}">
        <div class="security-item-head">
          <strong>${escapeHtml(ev.risk_level || "--")} · ${ev.risk_score ?? "--"} 分 · ${escapeHtml(ev.asset_group || "--")}</strong>
          <span>${escapeHtml(ev.window_kind === "short" ? "短窗口" : "长窗口")} ${escapeHtml(ev.window_start || "")} ~ ${escapeHtml(ev.window_end || "")}</span>
        </div>
        <p>规则命中：${escapeHtml(rules)}｜操作员（${ev.operator_count ?? (ev.operators || []).length}）：${escapeHtml(ops)}</p>
        ${notes ? `<p>判定依据：${escapeHtml(notes)}</p>` : ""}
        <p>处置状态：<code>${escapeHtml(dispose.status || "待复核")}</code>${dispose.disposer ? `（${escapeHtml(dispose.disposer)} ${escapeHtml(dispose.time || "")}）` : ""}</p>
        <div class="section-actions">
          <button class="button ghost small" data-collusion-action="detail">查看详情</button>
          <button class="button ghost small" data-collusion-action="export">导出证据链</button>
          <button class="button ghost small" data-collusion-action="dispose">处置</button>
        </div>
      </div>`;
  }).join("");
}

async function loadCollusion(options = {}) {
  if (!els.collusionEventList) return;
  try {
    const level = els.collusionLevelFilter?.value || "";
    const status = els.collusionStatusFilter?.value || "";
    const [overviewText, eventsText] = await Promise.all([
      request("/collusion/overview"),
      request(`/collusion/events?level=${encodeURIComponent(level)}&status=${encodeURIComponent(status)}&limit=50`),
    ]);
    const overview = parseJson(overviewText, {});
    const events = parseJson(eventsText, { events: [] });
    renderCollusionOverview(overview);
    renderCollusionEvents(events.events || []);
    els.collusionSummary.textContent =
      `高危 ${counts(overview, "HIGH")} / 中危 ${counts(overview, "MID")} / 待复核 ${overview.pending_review ?? 0}`;
    // 配置/规则/工单仅在首次进入面板时拉取，避免自动刷新覆盖正在编辑的内容
    if (!state.collusionConfigLoaded) {
      const [cfgText, rulesText, woText] = await Promise.all([
        request("/collusion/config"),
        request("/collusion/rules"),
        request("/collusion/workorders"),
      ]);
      if (els.collusionConfigText) els.collusionConfigText.value = cfgText;
      if (els.collusionRulesText) els.collusionRulesText.value = rulesText;
      if (els.collusionWorkordersText) els.collusionWorkordersText.value = woText;
      state.collusionConfigLoaded = true;
    }
  } catch (err) {
    els.collusionSummary.textContent = "加载失败";
    if (!options.silent) showNotice(err.message, "error");
  }

  function counts(o, level) {
    return o.event_counts?.[level] ?? 0;
  }
}

async function handleCollusionAction(action, eventId) {
  if (action === "detail") {
    try {
      const text = await request(`/collusion/events/detail?id=${encodeURIComponent(eventId)}`);
      els.collusionReportView.textContent = JSON.stringify(parseJson(text, {}), null, 2);
      showNotice("事件详情（含证据时间线）已输出到报表区域。");
    } catch (err) {
      showNotice(err.message, "error");
    }
    return;
  }
  if (action === "export") {
    try {
      const text = await request(`/collusion/events/export?id=${encodeURIComponent(eventId)}`);
      const blob = new Blob([JSON.stringify(parseJson(text, {}), null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `${eventId}.json`;
      link.click();
      URL.revokeObjectURL(url);
      recordOperation({
        object: `合谋风险事件 ${eventId}`,
        type: "export_collusion_evidence",
        details: "导出完整证据链 JSON",
        status: "success",
      });
    } catch (err) {
      showNotice(err.message, "error");
    }
    return;
  }
  if (action === "dispose") {
    const status = window.prompt(
      "处置状态（确认合谋攻击 / 合法运维（误报） / 待进一步调查）：",
      "合法运维（误报）",
    );
    if (!status) return;
    const note = window.prompt("处置说明（将记入合谋检测审计日志）：", "") || "";
    try {
      await request("/collusion/events/dispose", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ event_id: eventId, status, disposer: state.currentUser || "admin", note }),
      });
      recordOperation({
        object: `合谋风险事件 ${eventId}`,
        type: "collusion_dispose",
        details: `处置为「${status}」：${note}`,
        status: "success",
      });
      showNotice("处置完成，已写入审计日志。");
      await loadCollusion({ silent: true });
    } catch (err) {
      showNotice(err.message, "error");
      recordOperation({
        object: `合谋风险事件 ${eventId}`,
        type: "collusion_dispose",
        details: `处置为「${status}」失败`,
        status: "failure",
        error: err,
      });
    }
  }
}

async function saveCollusionDoc(path, textarea, label, recordType) {
  if (!textarea) return;
  try {
    await request(path, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: textarea.value,
    });
    showNotice(`${label}已保存并热生效。`);
    recordOperation({ object: label, type: recordType, details: `保存${label}成功`, status: "success" });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({ object: label, type: recordType, details: `保存${label}失败`, status: "failure", error: err });
  }
}

async function toggleCollusionEmergency() {
  const enable = els.collusionEmergencyBtn.textContent.startsWith("开启");
  try {
    await request("/collusion/emergency", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        enabled: enable,
        duration_minutes: 120,
        actor: state.currentUser || "admin",
      }),
    });
    recordOperation({
      object: "合谋检测应急运维模式",
      type: "collusion_emergency",
      details: enable ? "开启应急模式 120 分钟（风险等级自动降一级）" : "解除应急模式",
      status: "success",
    });
    showNotice(enable ? "应急运维模式已开启（120 分钟内风险等级自动降一级）。" : "应急运维模式已解除。");
    await loadCollusion({ silent: true });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: "合谋检测应急运维模式",
      type: "collusion_emergency",
      details: enable ? "开启应急模式失败" : "解除应急模式失败",
      status: "failure",
      error: err,
    });
  }
}

async function generateCollusionReport() {
  const days = Math.max(1, Math.min(180, parseInt(els.collusionReportDays?.value, 10) || 7));
  try {
    const text = await request(`/collusion/report?days=${days}`);
    els.collusionReportView.textContent = JSON.stringify(parseJson(text, {}), null, 2);
    showNotice(`近 ${days} 天合谋行为分析报表已生成。`);
  } catch (err) {
    showNotice(err.message, "error");
  }
}

// ---------------- 单页视图路由（侧边栏导航切换） ----------------

const VIEW_DEFAULT = "#overview";
const routerState = { current: "", navDepth: 0 };
const loadedViews = new Set();

// 各视图首次激活时的惰性数据加载器（会话期间只触发一次，避免无谓请求）
const VIEW_LOADERS = {
  "#database": () => loadDbHosts(),
  "#connection-requests": () => loadConnectionRequests({ silent: true }),
  "#operators": () => loadOperators({ silent: true }),
};

function knownViews() {
  return [...document.querySelectorAll(".nav-link")]
    .map((link) => link.getAttribute("href"))
    .filter((hash) => hash && hash.startsWith("#") && document.querySelector(hash));
}

function normalizeView(hash) {
  return knownViews().includes(hash) ? hash : VIEW_DEFAULT;
}

// 渲染指定视图：只显示对应 section，更新导航高亮、顶栏标题与返回按钮。
// 纯 DOM 切换，不刷新页面，登录 Token 等会话状态保持不变。
function renderView(hash, options = {}) {
  const view = normalizeView(hash);
  document.querySelectorAll(".content > .section").forEach((section) => {
    section.classList.toggle("view-active", `#${section.id}` === view);
  });
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.classList.toggle("active", link.getAttribute("href") === view);
  });
  const activeLink = document.querySelector(`.nav-link[href="${view}"]`);
  if (els.currentViewTitle && activeLink) {
    els.currentViewTitle.textContent = activeLink.textContent.trim();
  }
  if (els.viewBackBtn) els.viewBackBtn.hidden = view === VIEW_DEFAULT;
  if (!options.initial && view !== routerState.current) {
    // 切换后回到内容顶部，防止新视图停留在上个视图的滚动位置
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
  }
  routerState.current = view;

  // 仅在已登录后惰性加载（未登录时的 401 会打断登录页），每个视图会话内只触发一次
  if (state.token && !loadedViews.has(view)) {
    loadedViews.add(view);
    const loader = VIEW_LOADERS[view];
    if (loader) {
      Promise.resolve()
        .then(() => loader())
        .catch(() => {});
    }
  }
}

// 编程式导航：写入历史栈（支持浏览器前进/后退与返回按钮）
function navigateTo(hash) {
  const view = normalizeView(hash);
  if (view === routerState.current && window.location.hash === view) return;
  routerState.navDepth += 1;
  history.pushState({ afView: view }, "", view);
  renderView(view);
}

function goBackOrOverview() {
  if (routerState.navDepth > 0) {
    history.back();
  } else {
    navigateTo(VIEW_DEFAULT);
  }
}

function initRouter() {
  // 侧边栏导航：拦截默认锚点跳转，改走视图路由（侧边栏始终固定可见）
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", (event) => {
      const hash = link.getAttribute("href");
      if (hash && hash.startsWith("#")) {
        event.preventDefault();
        navigateTo(hash);
      }
    });
  });
  // 浏览器前进/后退
  window.addEventListener("popstate", () => {
    routerState.navDepth = Math.max(0, routerState.navDepth - 1);
    renderView(normalizeView(window.location.hash || VIEW_DEFAULT));
  });
  // 初始视图：尊重地址栏 hash（刷新/书签/分享链接可恢复到指定界面）
  const initial = normalizeView(window.location.hash || VIEW_DEFAULT);
  if (window.location.hash !== initial) {
    history.replaceState({ afView: initial }, "", initial);
  }
  renderView(initial, { initial: true });
}

// 兼容既有调用：平滑切换到目标视图，返回目标是否存在。
function gotoSection(selector) {
  if (!document.querySelector(selector)) return false;
  navigateTo(selector);
  return true;
}

// ---------------- 客户端连接请求 ----------------

async function loadConnectionRequests(options = {}) {
  if (!els.connectionList) return;
  try {
    const text = await request("/connection-requests", { timeoutMs: 8000 });
    const data = parseJson(text, { requests: [] });
    const items = data.requests || [];
    els.connectionCount.textContent = `${items.length} 条记录`;
    if (items.length === 0) {
      els.connectionList.innerHTML = `<tr><td colspan="7" class="empty-cell">暂无客户端连接记录。</td></tr>`;
      return;
    }
    els.connectionList.innerHTML = items.map((item) => {
      const hostId = item.host_id || "";
      return `
      <tr>
        <td><code>${escapeHtml(hostId || "--")}</code></td>
        <td>${escapeHtml(item.name || "--")}</td>
        <td>${escapeHtml(item.ip_address || "--")}</td>
        <td>${escapeHtml(item.os_version || "--")}</td>
        <td>${escapeHtml(item.last_seen || "--")}</td>
        <td><span class="pill ${item.online ? "ok" : "error"}">${item.online ? "在线" : "离线"}</span></td>
        <td>${hostId ? `<button class="button ghost small" type="button" data-db-host="${escapeHtml(hostId)}">查看数据库</button>` : "--"}</td>
      </tr>
    `;
    }).join("");
  } catch (err) {
    els.connectionCount.textContent = "加载失败";
    els.connectionList.innerHTML = `<tr><td colspan="7" class="empty-cell">加载连接请求失败：${escapeHtml(err.message)}</td></tr>`;
    if (!options.silent) showNotice(err.message, "error");
  }
}

// 从连接请求/其他页面联动进入数据库界面：跳转后刷新主机列表、预选主机并自动查询。
async function openHostDatabase(hostId) {
  if (!hostId) return;
  gotoSection("#database");
  try {
    const hosts = await loadDbHosts();
    if (!hosts.includes(hostId)) {
      showNotice(`主机 ${hostId} 暂无独立数据库（可能尚未上报日志数据）。`, "error");
      if (els.dbHostSelect) els.dbHostSelect.value = "";
      return;
    }
    if (els.dbHostSelect) els.dbHostSelect.value = hostId;
    await queryDatabase(0);
  } catch (err) {
    showNotice(err.message, "error");
  }
}

// ---------------- 操作员台账（M5-4） ----------------

// 操作员绑定基线：用于识别换机/换绑（首次登记只建基线，不算变更）
const operatorState = {
  list: [],
  bindings: parseJson(localStorage.getItem("af.operatorBindings") || "{}", {}),
  changes: parseJson(localStorage.getItem("af.operatorBindingChanges") || "[]", []),
};

function filteredOperators(operators) {
  const keyword = String(els.operatorSearch?.value || "").trim().toLowerCase();
  const status = els.operatorStatusFilter?.value || "all";
  return operators.filter((op) => {
    if (status === "online" && !op.online) return false;
    if (status === "offline" && (op.online || op.status === "disabled")) return false;
    if (status === "disabled" && op.status !== "disabled") return false;
    if (!keyword) return true;
    const haystack = [
      op.operator_id,
      op.display_name,
      op.bound_host_id,
      op.last_client_ip,
    ].filter(Boolean).join(" ").toLowerCase();
    return haystack.includes(keyword);
  });
}

function renderOperatorHostOptions(selected = "") {
  if (!els.operatorHostSelect) return;
  const options = ['<option value="">不指定 / 不修改</option>'];
  let found = !selected;
  state.hosts.forEach((host) => {
    const value = host.id || "";
    if (!value) return;
    if (value === selected) found = true;
    options.push(`<option value="${escapeHtml(value)}">${escapeHtml(host.name || value)}（${escapeHtml(value)}）</option>`);
  });
  if (!found) {
    options.push(`<option value="${escapeHtml(selected)}">${escapeHtml(selected)}（当前绑定）</option>`);
  }
  els.operatorHostSelect.innerHTML = options.join("");
  els.operatorHostSelect.value = selected;
}

function trackOperatorBindings(operators) {
  const detectedAt = new Date().toISOString();
  const next = {};
  operators.forEach((op) => {
    const id = op.operator_id;
    if (!id) return;
    const host = op.bound_host_id || "";
    next[id] = host;
    if (!Object.prototype.hasOwnProperty.call(operatorState.bindings, id)) return;
    const prev = operatorState.bindings[id] || "";
    if (prev === host) return;
    operatorState.changes.unshift({
      operator_id: id,
      display_name: op.display_name || "",
      from: prev,
      to: host,
      detected_at: detectedAt,
    });
  });
  operatorState.changes = operatorState.changes.slice(0, 50);
  operatorState.bindings = next;
  localStorage.setItem("af.operatorBindings", JSON.stringify(next));
  localStorage.setItem("af.operatorBindingChanges", JSON.stringify(operatorState.changes));
  renderOperatorBindings();
}

function renderOperatorBindings() {
  if (!els.operatorBindingList) return;
  const changes = operatorState.changes || [];
  els.operatorBindingSummary.textContent = changes.length
    ? `最近 ${changes.length} 次变更`
    : "未检测到绑定变更";
  if (changes.length === 0) {
    els.operatorBindingList.innerHTML = `
      <div class="empty-state">
        <strong>暂无绑定变更</strong>
        <p>操作员首次登记会建立基线；后续换机或换绑将在此显示，便于审计复核。</p>
      </div>
    `;
    return;
  }
  els.operatorBindingList.innerHTML = changes.map((item) => `
    <article class="security-item warning">
      <div class="security-item-head">
        <strong>${escapeHtml(item.operator_id)} 绑定变更：${escapeHtml(item.from || "未绑定")} → ${escapeHtml(item.to || "未绑定")}</strong>
        <span class="severity warning">warning</span>
      </div>
      <p>${escapeHtml(formatLocalTime(item.detected_at))} · ${escapeHtml(item.display_name || "--")}</p>
    </article>
  `).join("");
}

function renderOperators(data) {
  const operators = Array.isArray(data.operators) ? data.operators : operatorState.list;
  operatorState.list = operators;
  const visible = filteredOperators(operators);
  const onlineCount = operators.filter((op) => op.online).length;
  const boundCount = operators.filter((op) => op.bound_host_id).length;
  els.operatorCount.textContent = visible.length === operators.length
    ? `${operators.length} 名操作员，${onlineCount} 名在线`
    : `显示 ${visible.length} / ${operators.length} 名操作员，${onlineCount} 名在线`;
  if (els.operatorTotal) els.operatorTotal.textContent = String(operators.length);
  if (els.operatorOnline) els.operatorOnline.textContent = String(onlineCount);
  if (els.operatorBound) els.operatorBound.textContent = String(boundCount);
  if (els.operatorUnbound) els.operatorUnbound.textContent = String(operators.length - boundCount);
  if (data.storage_path && els.operatorStoragePath) {
    els.operatorStoragePath.textContent = `台账文件：${data.storage_path}`;
  }

  if (operators.length === 0) {
    els.operatorList.innerHTML = `<tr><td colspan="8" class="empty-cell">暂无操作员记录。客户端心跳/操作日志上报 operator_id 后会自动登记，也可在上方手工登记。</td></tr>`;
    return;
  }
  if (visible.length === 0) {
    els.operatorList.innerHTML = `<tr><td colspan="8" class="empty-cell">没有匹配的操作员，请调整搜索关键字或状态筛选。</td></tr>`;
    return;
  }
  els.operatorList.innerHTML = visible.map((op) => {
    const disabled = op.status === "disabled";
    const statusPill = disabled
      ? `<span class="pill unknown">已禁用</span>`
      : `<span class="pill ${op.online ? "ok" : "error"}">${op.online ? "在线" : "离线"}</span>`;
    const dbAction = op.bound_host_id
      ? `<button class="button ghost small" type="button" data-operator-action="db" data-host-id="${escapeHtml(op.bound_host_id)}">查看主机库</button>`
      : "";
    return `
      <tr>
        <td><code>${escapeHtml(op.operator_id || "--")}</code></td>
        <td>${escapeHtml(op.display_name || "--")}</td>
        <td>${escapeHtml(op.bound_host_id || "未绑定")}</td>
        <td>${statusPill}</td>
        <td>${escapeHtml(op.last_seen ? formatLocalTime(op.last_seen) : "--")}</td>
        <td>${escapeHtml(op.registered_at ? formatLocalTime(op.registered_at) : "--")}</td>
        <td>${escapeHtml(op.last_client_ip || "--")}</td>
        <td class="section-actions">
          <button class="button ghost small" type="button" data-operator-action="edit" data-operator-id="${escapeHtml(op.operator_id || "")}">编辑</button>
          ${dbAction}
        </td>
      </tr>
    `;
  }).join("");
}

async function loadOperators(options = {}) {
  if (!els.operatorList) return;
  try {
    const text = await request("/operators", { timeoutMs: 8000 });
    const data = parseJson(text, { operators: [] });
    trackOperatorBindings(data.operators || []);
    renderOperators(data);
    renderOperatorHostOptions(els.operatorHostSelect?.value || "");
  } catch (err) {
    els.operatorCount.textContent = "加载失败";
    els.operatorList.innerHTML = `<tr><td colspan="8" class="empty-cell">加载操作员台账失败：${escapeHtml(err.message)}</td></tr>`;
    if (!options.silent) showNotice(err.message, "error");
  }
}

function fillOperatorForm(op) {
  if (!op) return;
  els.operatorId.value = op.operator_id || "";
  els.operatorName.value = op.display_name || "";
  els.operatorStatus.value = op.status === "disabled" ? "disabled" : "active";
  renderOperatorHostOptions(op.bound_host_id || "");
  els.operatorId.focus();
}

function resetOperatorForm() {
  els.operatorId.value = "";
  els.operatorName.value = "";
  els.operatorStatus.value = "active";
  renderOperatorHostOptions("");
}

async function saveOperator() {
  const errors = validateFields(["operatorId", "operatorName"]);
  if (errors.length) {
    showNotice(errors[0], "error");
    return;
  }
  const operatorId = els.operatorId.value.trim();
  const hostId = els.operatorHostSelect?.value || "";
  const payload = {
    operator_id: operatorId,
    display_name: els.operatorName.value.trim(),
    host_id: hostId,
    status: els.operatorStatus.value,
  };
  const done = setLoading(els.saveOperatorBtn, "保存中...");
  try {
    await request("/operators/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    showNotice(`操作员 ${operatorId} 已保存。`);
    recordOperation({
      object: `操作员 ${operatorId}`,
      type: "operator_register",
      details: `绑定主机：${hostId || "未指定"}；状态：${payload.status}`,
      status: "success",
    });
    await loadOperators({ silent: true });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: `操作员 ${operatorId}`,
      type: "operator_register",
      details: `绑定主机：${hostId || "未指定"}；状态：${payload.status}`,
      status: "failure",
      error: err,
    });
  } finally {
    done();
  }
}

// ---------------- 主机数据库管理 ----------------

const dbState = {
  hosts: [],
  columns: [],
  rows: [],
  offset: 0,
  limit: 50,
  total: -1, // 未知总数
  hostId: "",
  table: "events",
  search: "",
};

// 在途请求去重：路由惰性加载与“查看数据库”联动可能同时触发，避免重复渲染覆盖已选主机
let dbHostsInFlight = null;

async function loadDbHosts() {
  if (!els.dbHostSelect) return [];
  if (dbHostsInFlight) return dbHostsInFlight;
  dbHostsInFlight = (async () => {
    // 记住当前选择，刷新列表后尽量保持
    const previous = els.dbHostSelect.value;
    try {
      const text = await request("/db/hosts", { timeoutMs: 8000 });
      const data = parseJson(text, { hosts: [] });
      dbState.hosts = data.hosts || [];
      els.dbHostSelect.innerHTML = `<option value="">请选择主机</option>` +
        dbState.hosts.map((h) => `<option value="${escapeHtml(h)}">${escapeHtml(h)}</option>`).join("");
      if (previous && dbState.hosts.includes(previous)) els.dbHostSelect.value = previous;
      return dbState.hosts;
    } catch (err) {
      showNotice(err.message, "error");
      return [];
    } finally {
      dbHostsInFlight = null;
    }
  })();
  return dbHostsInFlight;
}

async function queryDatabase(offset = 0) {
  const hostId = els.dbHostSelect?.value || "";
  const table = els.dbTableSelect?.value || "events";
  const search = (els.dbSearch?.value || "").trim();
  const limit = Math.max(1, Math.min(5000, parseInt(els.dbLimit?.value, 10) || 50));
  if (!hostId) {
    showNotice("请先选择目标主机。", "error");
    return;
  }
  dbState.hostId = hostId;
  dbState.table = table;
  dbState.search = search;
  dbState.limit = limit;
  dbState.offset = offset;

  const qs = new URLSearchParams({ host_id: hostId, table, limit: String(limit), offset: String(offset) });
  if (search) qs.set("search", search);
  try {
    const text = await request(`/db/query?${qs}`, { timeoutMs: 15000 });
    const data = parseJson(text, { columns: [], rows: [], count: 0 });
    dbState.columns = data.columns || [];
    dbState.rows = data.rows || [];
    renderDbResult();
    recordOperation({
      object: `主机数据库 ${hostId}/${table}`,
      type: "db_query",
      details: `查询第 ${offset / limit + 1} 页，返回 ${data.count} 条`,
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: `主机数据库 ${hostId}/${table}`,
      type: "db_query",
      details: "查询失败",
      status: "failure",
      error: err,
    });
  }
}

function renderDbResult() {
  if (!els.dbResultHead || !els.dbResultBody) return;
  const cols = dbState.columns;
  const rows = dbState.rows;
  els.dbResultInfo.textContent = `主机 ${dbState.hostId} · 表 ${dbState.table} · 返回 ${rows.length} 条（第 ${dbState.offset / dbState.limit + 1} 页）`;

  els.dbResultHead.innerHTML = `<tr>${cols.map((c) => `<th>${escapeHtml(c)}</th>`).join("")}</tr>`;
  if (rows.length === 0) {
    els.dbResultBody.innerHTML = `<tr><td colspan="${cols.length}" class="empty-cell">暂无数据。</td></tr>`;
  } else {
    els.dbResultBody.innerHTML = rows.map((row) =>
      `<tr>${row.map((cell) => `<td class="db-cell" title="${escapeHtml(cell)}">${escapeHtml(cell.length > 80 ? cell.slice(0, 80) + "…" : cell)}</td>`).join("")}</tr>`
    ).join("");
  }

  els.dbPagination.style.display = rows.length > 0 || dbState.offset > 0 ? "flex" : "none";
  els.dbPageInfo.textContent = `第 ${dbState.offset / dbState.limit + 1} 页 · 每页 ${dbState.limit} 条`;
  els.dbPrevPage.disabled = dbState.offset === 0;
  els.dbNextPage.disabled = rows.length < dbState.limit;
}

async function exportDatabase() {
  const hostId = els.dbHostSelect?.value || "";
  const table = els.dbTableSelect?.value || "events";
  if (!hostId) {
    showNotice("请先选择目标主机。", "error");
    return;
  }
  try {
    const text = await request(`/db/export?host_id=${encodeURIComponent(hostId)}&table=${encodeURIComponent(table)}`, { timeoutMs: 30000 });
    const blob = new Blob([text], { type: "application/x-ndjson" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `auditforwarder_${hostId}_${table}_${new Date().toISOString().slice(0, 10)}.ndjson`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showNotice(`已导出 ${hostId}/${table} 数据。`);
    recordOperation({
      object: `主机数据库 ${hostId}/${table}`,
      type: "db_export",
      details: "导出 NDJSON 文件",
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: `主机数据库 ${hostId}/${table}`,
      type: "db_export",
      details: "导出失败",
      status: "failure",
      error: err,
    });
  }
}

function renderCollectorCounts(data) {
  const totals = data.collector_totals || {};
  const entries = Object.entries(totals).sort((a, b) => b[1] - a[1]);
  if (entries.length === 0) {
    els.collectorCounts.innerHTML = `<span class="muted">暂无已存储日志</span>`;
  } else {
    const grandTotal = entries.reduce((sum, [, n]) => sum + n, 0);
    els.collectorCounts.innerHTML = entries.map(([collector, n]) => {
      const pct = grandTotal > 0 ? Math.round((n / grandTotal) * 1000) / 10 : 0;
      const tag = collector === "etw_win"
        ? '<span class="severity warning">ETW 安全日志</span>'
        : collector === "legacy"
          ? '<span class="severity info">旧日志迁移</span>'
          : "";
      return `<span><code>${escapeHtml(collector)}</code> ${tag}<em>${formatNumber(n)} 条 · ${pct}%</em></span>`;
    }).join("");
  }
  const hosts = data.hosts || {};
  const hostNames = Object.keys(hosts);
  els.collectorCountsDetail.textContent = hostNames.length === 0
    ? "暂无按主机明细"
    : JSON.stringify({ total: data.total || 0, hosts }, null, 2);
}

function formatLatencyMs(value) {
  if (value === undefined || value === null || Number.isNaN(Number(value))) return "--";
  return `${Number(value).toFixed(0)} ms`;
}

function renderTransferLatency(data) {
  const hi = data.high || {};
  const nm = data.normal || {};
  els.latencyHighAvg.textContent = formatLatencyMs(hi.avg_ms);
  els.latencyNormalAvg.textContent = formatLatencyMs(nm.avg_ms);
  els.latencyHighCount.textContent = `${formatNumber(hi.count || 0)} 条样本`;
  els.latencyNormalCount.textContent = `${formatNumber(nm.count || 0)} 条样本`;
  els.latencyP95.textContent = `${formatLatencyMs(hi.p95_ms)} / ${formatLatencyMs(nm.p95_ms)}`;
  const ratio = Number(data.avg_latency_ratio);
  if (!ratio || Number.isNaN(ratio)) {
    els.latencyRatio.textContent = "--";
    els.latencyTarget.textContent = "样本不足";
  } else {
    els.latencyRatio.textContent = ratio.toFixed(2);
    const met = Boolean(data.target_met);
    els.latencyTarget.textContent = met ? "达标（≤ 0.5）" : `未达标（目标 ≤ ${data.target_ratio_le || 0.5}）`;
    els.latencyTarget.className = met ? "latency-ok" : "latency-bad";
  }
}

function filterProfileRow(profile = {}) {
  const collector = profile.collector || "";
  const mode = profile.mode === "lenient" ? "lenient" : "strict";
  const maxLen = Number.isFinite(Number(profile.message_max_len)) ? Number(profile.message_max_len) : 512;
  const retention = Number.isFinite(Number(profile.retention_lines)) ? Number(profile.retention_lines) : 50000;
  const drops = Array.isArray(profile.drop_fields) ? profile.drop_fields.join(", ") : "";
  const note = profile.note ? escapeHtml(profile.note) : "";
  return `
    <tr class="filter-profile-row">
      <td><input class="profile-collector" type="text" value="${escapeHtml(collector)}" placeholder="如 process_win / default" style="width:11rem"></td>
      <td>
        <select class="profile-mode">
          <option value="strict"${mode === "strict" ? " selected" : ""}>strict 严格</option>
          <option value="lenient"${mode === "lenient" ? " selected" : ""}>lenient 宽松</option>
        </select>
      </td>
      <td><input class="profile-maxlen" type="number" min="64" max="1048576" value="${maxLen}" style="width:7rem"></td>
      <td><input class="profile-retention" type="number" min="100" max="5000000" value="${retention}" style="width:8rem"></td>
      <td><input class="profile-dropfields" type="text" value="${escapeHtml(drops)}" placeholder="raw_xml, raw_payload" style="width:13rem"></td>
      <td><button type="button" class="button danger small profile-remove">删除</button></td>
    </tr>
    ${note ? `<tr><td colspan="6" class="muted profile-note-row">${note}</td></tr>` : ""}`;
}

function renderFilterProfiles(profiles) {
  const rows = Array.isArray(profiles) ? profiles : [];
  els.filterProfileRows.innerHTML = rows.map(filterProfileRow).join("") || filterProfileRow({ mode: "strict" });
}

function collectFilterProfiles() {
  const profiles = [];
  const seen = new Set();
  const blocks = els.filterProfileRows.querySelectorAll(".filter-profile-row");
  blocks.forEach((row) => {
    const collector = row.querySelector(".profile-collector").value.trim();
    const mode = row.querySelector(".profile-mode").value;
    const messageMaxLen = Number(row.querySelector(".profile-maxlen").value);
    const retentionLines = Number(row.querySelector(".profile-retention").value);
    const dropFields = row.querySelector(".profile-dropfields").value
      .split(",").map((s) => s.trim()).filter(Boolean);
    if (!collector) return;
    if (!/^[a-z0-9_]{2,32}$/.test(collector)) {
      throw new Error(`采集器 ID 不合法：${collector}（仅允许小写字母、数字、下划线，2-32 位）`);
    }
    if (seen.has(collector)) throw new Error(`采集器 ID 重复：${collector}`);
    seen.add(collector);
    if (!Number.isFinite(messageMaxLen) || messageMaxLen < 64) {
      throw new Error(`${collector} 的消息最大长度必须 ≥ 64`);
    }
    if (!Number.isFinite(retentionLines) || retentionLines < 100) {
      throw new Error(`${collector} 的保留行数必须 ≥ 100`);
    }
    profiles.push({
      collector,
      mode,
      message_max_len: Math.round(messageMaxLen),
      drop_fields: dropFields,
      retention_lines: Math.round(retentionLines),
    });
  });
  if (profiles.length === 0) throw new Error("至少保留一条过滤策略");
  if (!seen.has("default")) throw new Error("必须保留 collector=default 的兜底策略");
  return profiles;
}

async function saveFilterProfiles() {
  let profiles;
  try {
    profiles = collectFilterProfiles();
  } catch (err) {
    els.filterProfileMsg.textContent = err.message;
    showNotice(err.message, "error");
    return;
  }
  const done = setLoading(els.saveFilterProfilesBtn, "保存中...");
  try {
    const text = await request("/log-filter/profiles", {
      method: "PUT",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({ profiles }),
    });
    const result = parseJson(text, {});
    els.filterProfileMsg.textContent = result.saved ? "已保存，新日志立即按新策略过滤" : "已提交";
    showNotice("日志过滤策略已保存。");
  } catch (err) {
    els.filterProfileMsg.textContent = err.message;
    showNotice(err.message, "error");
  } finally {
    done();
  }
}

async function loadLogPolicy(options = {}) {
  if (!els.filterProfileRows) return;
  const silent = Boolean(options && options.silent);
  const skipProfiles = Boolean(options && options.skipProfiles);
  const host = els.logPolicyHost.value.trim();
  const qs = host ? `?host_id=${encodeURIComponent(host)}` : "";
  try {
    const tasks = [
      request(`/logs/collector-counts${qs}`),
      request(`/stats/transfer-latency${qs}${qs ? "&" : "?"}limit=5000`),
    ];
    if (!skipProfiles) tasks.push(request("/log-filter/profiles"));
    const [countsText, latencyText, profilesText] = await Promise.all(tasks);
    renderCollectorCounts(parseJson(countsText, { collector_totals: {}, hosts: {} }));
    renderTransferLatency(parseJson(latencyText, {}));
    if (!skipProfiles) renderFilterProfiles(parseJson(profilesText, { profiles: [] }).profiles);
    els.logPolicySummary.textContent = host ? `主机 ${host} 的统计` : "全部主机汇总";
  } catch (err) {
    els.logPolicySummary.textContent = "加载失败";
    if (!silent) showNotice(err.message, "error");
  }
}

async function loadHostHistory(hostId, kind) {
  if (!hostId) return;
  const labels = {
    metrics: "资源指标",
    audit: "审计摘要",
    commands: "命令结果",
    logs: "操作日志",
    alerts: "告警历史",
  };
  const label = labels[kind] || "资源指标";
  els.hostHistoryTitle.textContent = `正在加载 ${hostId} 的${label}...`;
  els.hostHistoryOutput.textContent = "加载中...";
  try {
    const text = await request(`/hosts/history?host_id=${encodeURIComponent(hostId)}&kind=${encodeURIComponent(kind)}`);
    const data = parseJson(text, {});
    const lines = String(data.jsonl || "")
      .split(/\r?\n/)
      .filter(Boolean)
      .slice(-20)
      .map((line) => {
        const parsed = parseJson(line, null);
        return parsed ? JSON.stringify(parsed, null, 2) : line;
      });
    els.hostHistoryTitle.textContent = `${hostId} 的${label}，最近 ${lines.length} 条`;
    els.hostHistoryOutput.textContent = lines.length > 0 ? lines.join("\n\n") : "暂无历史数据。";
    recordOperation({
      object: hostId,
      type: "view_host_history",
      details: `查看${label}历史`,
      status: "success",
    });
  } catch (err) {
    els.hostHistoryTitle.textContent = `${hostId} 的${label}加载失败`;
    els.hostHistoryOutput.textContent = err.message;
    showNotice(err.message, "error");
  }
}

function resetHostForm() {
  els.hostId.value = "";
  els.hostName.value = "";
  els.hostIp.value = "";
  els.hostHardware.value = "";
  els.hostOs.value = "";
  els.hostPermissions.value = "remote_control";
  els.hostNote.value = "";
  ["hostId", "hostName", "hostIp", "hostHardware", "hostOs", "hostPermissions", "hostNote"].forEach((id) => {
    if (els[id]) {
      els[id].classList.remove("invalid", "valid");
      const node = els[id].closest(".field")?.querySelector(".field-feedback");
      if (node) node.textContent = "";
    }
  });
}

function fillHostForm(host) {
  els.hostId.value = host.id || "";
  els.hostName.value = host.name || "";
  els.hostIp.value = host.ip_address || "";
  els.hostHardware.value = host.hardware || "";
  els.hostOs.value = host.os_version || "";
  els.hostPermissions.value = (host.permissions || []).join(",");
  els.hostNote.value = host.note || "";
  els.remoteHostId.value = host.id || "";
  validateFields(["hostId", "hostName", "hostIp", "hostHardware", "hostOs", "hostPermissions", "hostNote", "remoteHostId"]);
  navigateTo("#hosts");
}

async function saveHost() {
  if (!validateFields(["hostId", "hostName", "hostIp", "hostHardware", "hostOs", "hostPermissions", "hostNote"])) {
    recordOperation({
      object: "主机信息",
      type: "validate_host_form",
      details: "前端验证失败，未提交主机信息",
      status: "failure",
    });
    return;
  }
  const host = {
    id: els.hostId.value.trim(),
    name: els.hostName.value.trim(),
    ip_address: els.hostIp.value.trim(),
    hardware: els.hostHardware.value.trim(),
    os_version: els.hostOs.value.trim(),
    permissions: permissionList(els.hostPermissions.value),
    note: els.hostNote.value.trim(),
  };
  const exists = Boolean(host.id && state.hosts.some((item) => item.id === host.id));
  const done = setLoading(els.saveHostBtn, "保存中...");
  try {
    const text = await request(exists ? `/hosts?id=${encodeURIComponent(host.id)}` : "/hosts", {
      method: exists ? "PUT" : "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify(host),
    });
    renderHosts(parseJson(text, { hosts: [] }));
    showNotice("主机信息已保存。");
    recordOperation({
      object: host.name,
      type: exists ? "update_host" : "add_host",
      details: `主机ID=${host.id || "自动生成"}，权限=${host.permissions.join(",") || "status_view"}`,
      status: "success",
    });
    resetHostForm();
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: host.name || "主机信息",
      type: exists ? "update_host" : "add_host",
      details: "保存主机信息失败",
      status: "failure",
      error: err,
    });
  } finally {
    done();
  }
}

async function deleteHost(hostId) {
  if (!hostId) return;
  const host = state.hosts.find((item) => item.id === hostId);
  const label = host?.name || hostId;
  if (!window.confirm(`确认删除主机“${label}”吗？该操作会从监管列表移除该主机信息。`)) return;
  try {
    const text = await request(`/hosts?id=${encodeURIComponent(hostId)}`, { method: "DELETE" });
    renderHosts(parseJson(text, { hosts: [] }));
    showNotice("主机信息已删除。");
    recordOperation({
      object: host?.name || hostId,
      type: "delete_host",
      details: `删除主机ID=${hostId}`,
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: host?.name || hostId,
      type: "delete_host",
      details: `删除主机ID=${hostId}失败`,
      status: "failure",
      error: err,
    });
  }
}

async function sendRemoteCommand() {
  if (!validateFields(["remoteHostId", "remotePayload"])) {
    recordOperation({
      object: "远程控制指令",
      type: "validate_remote_command",
      details: "前端验证失败，未发送远控指令",
      status: "failure",
    });
    return;
  }
  const targetHostId = els.remoteHostId.value.trim();
  const commandType = els.remoteCommandType.value;
  const payload = els.remotePayload.value.trim();
  const done = setLoading(els.sendRemoteCommandBtn, "发送中...");
  try {
    const text = await request("/remote/control", {
      method: "POST",
      headers: { "Content-Type": "application/json; charset=utf-8" },
      body: JSON.stringify({
        target_host_id: targetHostId,
        command_type: commandType,
        payload,
      }),
    });
    const data = parseJson(text, {});
    showNotice(`远程指令已进入目标主机队列：${data.command_id || "已接受"}`);
    recordOperation({
      object: targetHostId,
      type: "send_remote_command",
      details: `指令类型=${commandType}，队列ID=${data.command_id || "--"}，加密=${data.queue_encryption || "AES-256-GCM"}`,
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: targetHostId,
      type: "send_remote_command",
      details: `发送远控指令失败，指令类型=${commandType}`,
      status: "failure",
      error: err,
    });
  } finally {
    done();
  }
}

function shortHash(value) {
  const text = String(value || "--");
  if (text.length <= 18) return text;
  return `${text.slice(0, 10)}...${text.slice(-8)}`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function refreshAll(options = {}) {
  if (!state.token) {
    showLogin();
    return;
  }
  if (state.refreshInFlight) return;
  state.refreshInFlight = true;
  const record = options.record !== false;
  const silent = Boolean(options.silent);
  const done = silent ? () => {} : setLoading(els.refreshBtn, "刷新中...");
  try {
    const [statusText, configText, batchesText, hostsText] = await Promise.all([
      request("/status"),
      request("/config"),
      request("/batches"),
      request("/hosts"),
    ]);
    renderStatus(parseJson(statusText, {}));
    renderConfig(configText);
    renderBatches(parseJson(batchesText, { batches: [] }));
    renderHosts(parseJson(hostsText, { hosts: [] }));
    await loadSecurityMonitor({ silent });
    await loadCollusion({ silent });
    await loadLogPolicy({ silent });
    await loadConnectionRequests({ silent });
    await loadOperators({ silent: true });
    if (!silent) showNotice("数据已刷新。");
    if (record) {
      recordOperation({
        object: "管理控制台数据",
        type: "refresh_dashboard",
        details: "刷新运行状态、配置快照、证据批次和主机列表",
        status: "success",
      });
    }
  } catch (err) {
    els.statusPill.textContent = "异常";
    els.statusPill.className = "pill error";
    if (!silent) showNotice(err.message, "error");
    if (record) {
      recordOperation({
        object: "管理控制台数据",
        type: "refresh_dashboard",
        details: "刷新运行状态、配置快照、证据批次和主机列表失败",
        status: "failure",
        error: err,
      });
    }
  } finally {
    state.refreshInFlight = false;
    done();
  }
}

async function refreshLiveData() {
  if (!state.token || !state.autoRefresh || state.liveRefreshInFlight || document.hidden) return;
  state.liveRefreshInFlight = true;
  try {
    const [statusText, hostsText] = await Promise.all([
      request("/status", { timeoutMs: 8000 }),
      request("/hosts", { timeoutMs: 8000 }),
    ]);
    renderStatus(parseJson(statusText, {}));
    renderHosts(parseJson(hostsText, { hosts: [] }));
    await loadSecurityMonitor({ silent: true });
    await loadCollusion({ silent: true });
    await loadLogPolicy({ silent: true, skipProfiles: true });
    await loadConnectionRequests({ silent: true });
    await loadOperators({ silent: true });
  } catch (err) {
    els.statusPill.textContent = "连接异常";
    els.statusPill.className = "pill error";
    els.lastUpdated.textContent = `刷新失败：${err.message}`;
  } finally {
    state.liveRefreshInFlight = false;
  }
}

async function reloadConfig() {
  const done = setLoading(els.reloadConfigBtn, "加载中...");
  try {
    const text = await request("/config/reload", { method: "POST" });
    showNotice(`配置已重新加载：${text.replace(/\s+/g, " ").trim()}`);
    const configText = await request("/config");
    renderConfig(configText);
    recordOperation({
      object: "系统配置",
      type: "reload_config",
      details: "调用 /config/reload 并刷新配置快照",
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: "系统配置",
      type: "reload_config",
      details: "调用 /config/reload 失败",
      status: "failure",
      error: err,
    });
  } finally {
    done();
  }
}

async function submitUpgrade() {
  if (!validateFields(["upgradeUrl"])) {
    recordOperation({
      object: "远程升级",
      type: "validate_upgrade_url",
      details: "前端验证失败，未提交升级请求",
      status: "failure",
    });
    return;
  }
  const url = els.upgradeUrl.value.trim();
  const done = setLoading(els.upgradeBtn, "提交中...");
  try {
    const text = await request("/upgrade", {
      method: "POST",
      headers: { "Content-Type": "text/plain; charset=utf-8" },
      body: url,
    });
    showNotice(`升级请求已提交：${text.replace(/\s+/g, " ").trim()}`);
    recordOperation({
      object: url,
      type: "submit_upgrade",
      details: "调用 /upgrade 提交升级包 URL",
      status: "success",
    });
  } catch (err) {
    showNotice(err.message, "error");
    recordOperation({
      object: url,
      type: "submit_upgrade",
      details: "调用 /upgrade 提交升级包 URL 失败",
      status: "failure",
      error: err,
    });
  } finally {
    done();
  }
}

async function copyConfig() {
  if (!state.lastConfigText) return;
  try {
    await navigator.clipboard.writeText(state.lastConfigText);
    showNotice("配置内容已复制。");
    recordOperation({
      object: "当前配置快照",
      type: "copy_config",
      details: `复制配置内容，长度=${state.lastConfigText.length}`,
      status: "success",
    });
  } catch (err) {
    showNotice("当前浏览器不允许自动复制，请手动选择复制。", "error");
    recordOperation({
      object: "当前配置快照",
      type: "copy_config",
      details: "复制配置内容失败",
      status: "failure",
      error: err,
    });
  }
}

function openTokenDialog() {
  els.tokenInput.value = state.token;
  els.tokenDialog.classList.remove("hidden");
  els.tokenInput.focus();
}

function closeTokenDialog() {
  els.tokenDialog.classList.add("hidden");
}

function saveToken() {
  state.token = els.tokenInput.value.trim();
  if (state.token) localStorage.setItem("af.managerToken", state.token);
  else localStorage.removeItem("af.managerToken");
  closeTokenDialog();
  showNotice("Token 已保存，正在重新请求数据。");
  recordOperation({
    object: "管理接口 Token",
    type: "save_token",
    details: state.token ? "保存 Bearer Token，用于访问受保护接口" : "清空 Bearer Token",
    status: "success",
  });
  if (state.token) showApp();
  refreshAll();
}

function clearToken() {
  state.token = "";
  localStorage.removeItem("af.managerToken");
  els.tokenInput.value = "";
  showNotice("Token 已清除。");
  recordOperation({
    object: "管理接口 Token",
    type: "clear_token",
    details: "清除浏览器本地保存的 Bearer Token",
    status: "success",
  });
  closeTokenDialog();
  showLogin("Token 已清除，请重新登录。");
}

function saveActorIdentity() {
  state.actorIdentity = (els.actorIdentity.value || "本地控制台用户").trim();
  localStorage.setItem("af.actorIdentity", state.actorIdentity);
  recordOperation({
    object: "执行者身份",
    type: "update_actor_identity",
    details: `执行者身份更新为：${state.actorIdentity}`,
    status: "success",
  });
}

function bindNavigation() {
  // 导航已由单页视图路由接管（见 initRouter），此处保留函数名供 init 调用
  initRouter();
}

function init() {
  els.endpointText.textContent = window.location.host || "本机服务";
  els.actorIdentity.value = state.actorIdentity;
  if (els.loginForm) {
    els.loginForm.addEventListener("submit", login);
    els.loginForm.addEventListener("reset", () => {
      window.setTimeout(() => {
        if (els.loginMessage) els.loginMessage.className = "login-message hidden";
      }, 0);
    });
  }
  if (els.autoRefreshToggle) {
    els.autoRefreshToggle.checked = state.autoRefresh;
    els.autoRefreshToggle.addEventListener("change", () => {
      state.autoRefresh = els.autoRefreshToggle.checked;
      localStorage.setItem("af.autoRefresh", String(state.autoRefresh));
      showNotice(state.autoRefresh ? "已开启自动轻量刷新。" : "已暂停自动刷新。");
    });
  }
  els.refreshBtn.addEventListener("click", () => refreshAll());
  if (els.viewBackBtn) els.viewBackBtn.addEventListener("click", goBackOrOverview);
  if (els.refreshSecurityBtn) els.refreshSecurityBtn.addEventListener("click", () => loadSecurityMonitor());
  // 合谋检测面板：刷新 / 过滤 / 事件操作 / 配置规则工单保存 / 应急模式 / 报表
  if (els.refreshCollusionBtn) els.refreshCollusionBtn.addEventListener("click", () => loadCollusion());
  if (els.collusionLevelFilter) els.collusionLevelFilter.addEventListener("change", () => loadCollusion({ silent: true }));
  if (els.collusionStatusFilter) els.collusionStatusFilter.addEventListener("change", () => loadCollusion({ silent: true }));
  if (els.collusionEventList) els.collusionEventList.addEventListener("click", (event) => {
    const btn = event.target.closest("[data-collusion-action]");
    if (!btn) return;
    const item = btn.closest("[data-event-id]");
    if (item) handleCollusionAction(btn.getAttribute("data-collusion-action"), item.getAttribute("data-event-id"));
  });
  if (els.saveCollusionConfigBtn) els.saveCollusionConfigBtn.addEventListener("click",
    () => saveCollusionDoc("/collusion/config", els.collusionConfigText, "合谋检测配置", "save_collusion_config"));
  if (els.saveCollusionRulesBtn) els.saveCollusionRulesBtn.addEventListener("click",
    () => saveCollusionDoc("/collusion/rules", els.collusionRulesText, "合谋检测规则库", "save_collusion_rules"));
  if (els.saveCollusionWorkordersBtn) els.saveCollusionWorkordersBtn.addEventListener("click",
    () => saveCollusionDoc("/collusion/workorders", els.collusionWorkordersText, "工单注册表", "save_collusion_workorders"));
  if (els.collusionEmergencyBtn) els.collusionEmergencyBtn.addEventListener("click", toggleCollusionEmergency);
  if (els.collusionReportBtn) els.collusionReportBtn.addEventListener("click", generateCollusionReport);
  if (els.logCollectorFilter) els.logCollectorFilter.addEventListener("change", () => loadSecurityMonitor({ silent: true }));
  if (els.logPriorityFilter) els.logPriorityFilter.addEventListener("change", () => loadSecurityMonitor({ silent: true }));
  if (els.refreshLogPolicyBtn) els.refreshLogPolicyBtn.addEventListener("click", () => loadLogPolicy());
  if (els.logPolicyQueryBtn) els.logPolicyQueryBtn.addEventListener("click", () => loadLogPolicy());
  if (els.logPolicyHost) els.logPolicyHost.addEventListener("keydown", (event) => {
    if (event.key === "Enter") loadLogPolicy();
  });
  if (els.addFilterProfileBtn) els.addFilterProfileBtn.addEventListener("click", () => {
    els.filterProfileRows.insertAdjacentHTML("beforeend", filterProfileRow({ mode: "strict" }));
  });
  if (els.filterProfileRows) els.filterProfileRows.addEventListener("click", (event) => {
    if (!event.target.classList.contains("profile-remove")) return;
    const block = event.target.closest(".filter-profile-row");
    const noteRow = block ? block.nextElementSibling : null;
    if (block) block.remove();
    if (noteRow && noteRow.classList.contains("profile-note-row")) noteRow.remove();
  });
  if (els.saveFilterProfilesBtn) els.saveFilterProfilesBtn.addEventListener("click", saveFilterProfiles);
  els.reloadConfigBtn.addEventListener("click", reloadConfig);
  els.copyConfigBtn.addEventListener("click", copyConfig);
  els.saveHostBtn.addEventListener("click", saveHost);
  els.resetHostFormBtn.addEventListener("click", resetHostForm);
  els.sendRemoteCommandBtn.addEventListener("click", sendRemoteCommand);
  const updateHostFilter = debounce(() => {
    state.lastRenderedHostsKey = "";
    renderHosts({ hosts: state.hosts });
  });
  if (els.hostSearch) els.hostSearch.addEventListener("input", updateHostFilter);
  if (els.hostStatusFilter) els.hostStatusFilter.addEventListener("change", updateHostFilter);
  els.hostList.addEventListener("click", (event) => {
    const button = event.target.closest("[data-host-action]");
    if (!button) return;
    const hostId = button.getAttribute("data-host-id");
    const host = state.hosts.find((item) => item.id === hostId);
    const action = button.getAttribute("data-host-action");
    if (action === "edit" && host) fillHostForm(host);
    if (action === "select" && host) {
      els.remoteHostId.value = host.id;
      validateField(els.remoteHostId, validationRules.remoteHostId);
      showNotice(`已选择远控目标：${host.name || host.id}`);
    }
    if (action === "delete") deleteHost(hostId);
    if (action === "history-metrics") loadHostHistory(hostId, "metrics");
    if (action === "history-audit") loadHostHistory(hostId, "audit");
    if (action === "history-commands") loadHostHistory(hostId, "commands");
    if (action === "history-logs") loadHostHistory(hostId, "logs");
    if (action === "history-alerts") loadHostHistory(hostId, "alerts");
  });
  els.upgradeBtn.addEventListener("click", submitUpgrade);
  els.tokenBtn.addEventListener("click", openTokenDialog);
  els.cancelTokenBtn.addEventListener("click", closeTokenDialog);
  els.saveTokenBtn.addEventListener("click", saveToken);
  els.clearTokenBtn.addEventListener("click", clearToken);
  els.actorIdentity.addEventListener("change", saveActorIdentity);
  els.copyRecordsBtn.addEventListener("click", copyOperationRecords);
  els.exportRecordsBtn.addEventListener("click", exportOperationRecords);
  els.clearRecordsBtn.addEventListener("click", clearOperationRecords);
  // 连接请求与数据库管理
  if (els.refreshConnectionsBtn) els.refreshConnectionsBtn.addEventListener("click", () => loadConnectionRequests());
  // 操作员台账（M5-4）
  if (els.refreshOperatorsBtn) els.refreshOperatorsBtn.addEventListener("click", () => loadOperators());
  if (els.saveOperatorBtn) els.saveOperatorBtn.addEventListener("click", saveOperator);
  if (els.resetOperatorFormBtn) els.resetOperatorFormBtn.addEventListener("click", resetOperatorForm);
  const updateOperatorFilter = debounce(() => renderOperators({ operators: operatorState.list }));
  if (els.operatorSearch) els.operatorSearch.addEventListener("input", updateOperatorFilter);
  if (els.operatorStatusFilter) els.operatorStatusFilter.addEventListener("change", updateOperatorFilter);
  if (els.operatorList) els.operatorList.addEventListener("click", (event) => {
    const button = event.target.closest("[data-operator-action]");
    if (!button) return;
    const action = button.getAttribute("data-operator-action");
    if (action === "edit") {
      const operatorId = button.getAttribute("data-operator-id");
      fillOperatorForm(operatorState.list.find((item) => item.operator_id === operatorId));
    }
    if (action === "db") openHostDatabase(button.getAttribute("data-host-id"));
  });
  if (els.refreshDbHostsBtn) els.refreshDbHostsBtn.addEventListener("click", () => loadDbHosts());
  if (els.dbQueryBtn) els.dbQueryBtn.addEventListener("click", () => queryDatabase(0));
  if (els.dbExportBtn) els.dbExportBtn.addEventListener("click", exportDatabase);
  if (els.dbPrevPage) els.dbPrevPage.addEventListener("click", () => queryDatabase(Math.max(0, dbState.offset - dbState.limit)));
  if (els.dbNextPage) els.dbNextPage.addEventListener("click", () => queryDatabase(dbState.offset + dbState.limit));
  if (els.dbHostSelect) els.dbHostSelect.addEventListener("change", () => queryDatabase(0));
  if (els.dbSearch) els.dbSearch.addEventListener("keydown", (event) => {
    if (event.key === "Enter") queryDatabase(0);
  });
  // 主页快捷入口：拦截锚点默认跳转，统一走平滑滚动并立即高亮导航
  document.querySelectorAll("[data-quick-goto]").forEach((card) => {
    card.addEventListener("click", (event) => {
      event.preventDefault();
      gotoSection(card.getAttribute("data-quick-goto"));
    });
  });
  // 连接请求列表：点击“查看数据库”联动跳转到数据库界面并预选主机
  if (els.connectionList) els.connectionList.addEventListener("click", (event) => {
    const btn = event.target.closest("[data-db-host]");
    if (!btn) return;
    openHostDatabase(btn.getAttribute("data-db-host"));
  });
  els.tokenDialog.addEventListener("click", (event) => {
    if (event.target === els.tokenDialog) closeTokenDialog();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeTokenDialog();
  });
  bindNavigation();
  bindValidation();
  renderOperationRecords();
  if (state.token) {
    showApp();
    refreshAll({ record: false });
  } else {
    showLogin();
    if (els.loginUsername) els.loginUsername.focus();
  }
  // 实验模式：5 秒一次，合谋告警应 10 秒内出现在页面上。
  window.setInterval(refreshLiveData, 5000);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.token) refreshLiveData();
  });
}

init();
