/* ==========================================================================
   AI-Detective Corporate Redesign - API Client Wrapper
   ========================================================================== */

const API_BASE = window.location.origin;

/**
 * Wraps fetch request options with credentials policy and anti-CSRF headers.
 */
function getRequestOptions(options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = options.headers || {};
  
  // Custom header to bypass backend CSRF protection checks
  if (['POST', 'PUT', 'DELETE'].includes(method)) {
    headers['X-Requested-With'] = 'XMLHttpRequest';
  }

  return {
    ...options,
    headers,
    credentials: 'include' // Enforce passing cookies in CORS/SameSite requests
  };
}

export const api = {
  // Authentication endpoints
  async login(username, password) {
    const res = await fetch(`${API_BASE}/api/auth/login`, getRequestOptions({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    }));
    return res.json();
  },

  async register(username, password) {
    const res = await fetch(`${API_BASE}/api/auth/register`, getRequestOptions({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    }));
    return res.json();
  },

  async logout() {
    const res = await fetch(`${API_BASE}/api/auth/logout`, getRequestOptions({
      method: 'POST'
    }));
    return res.json();
  },

  // SAST & Code Reports
  async getReportsList() {
    const res = await fetch(`${API_BASE}/api/reports/list`, getRequestOptions());
    return res.json();
  },

  async getReport(id) {
    const res = await fetch(`${API_BASE}/api/reports/${id}`, getRequestOptions());
    if (res.status === 404) throw new Error('Report not found');
    return res.json();
  },

  async deleteReport(id) {
    const res = await fetch(`${API_BASE}/api/reports/${id}`, getRequestOptions({ method: 'DELETE' }));
    return res.json();
  },

  async runZipScan(formData) {
    const res = await fetch(`${API_BASE}/api/scan/upload`, getRequestOptions({
      method: 'POST',
      body: formData
    }));
    return res.json();
  },

  async runGitScan(gitUrl, branch) {
    const res = await fetch(`${API_BASE}/api/scan/git`, getRequestOptions({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ gitUrl, branch })
    }));
    return res.json();
  },

  async runPasteScan(code, filename, projectName) {
    const res = await fetch(`${API_BASE}/api/scan/paste`, getRequestOptions({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, filename, projectName })
    }));
    return res.json();
  },

  async launchAiAudit(id) {
    const res = await fetch(`${API_BASE}/api/scan/${id}/ai-analyze`, getRequestOptions({ method: 'POST' }));
    return res.json();
  },

  // WAPT & Dynamic Assessments
  async triggerWaptScan(targetUrl, authConfig, scanId) {
    const res = await fetch(`${API_BASE}/api/wapt/scan`, getRequestOptions({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl, authConfig, scanId })
    }));
    return res.json();
  },

  async getWaptLogs(scanId) {
    const res = await fetch(`${API_BASE}/api/wapt/scan/${scanId}/logs`, getRequestOptions());
    return res.json();
  },

  async getWaptReports() {
    const res = await fetch(`${API_BASE}/api/wapt/reports`, getRequestOptions());
    return res.json();
  },

  async getWaptReportDetails(id) {
    const res = await fetch(`${API_BASE}/api/wapt/reports/${id}`, getRequestOptions());
    if (res.status === 404) throw new Error('WAPT report not found');
    return res.json();
  },

  async getWaptBenchmarks() {
    const res = await fetch(`${API_BASE}/api/wapt/benchmark`, getRequestOptions());
    return res.json();
  },

  // Settings & Diagnostics
  async getDiagnostics() {
    const res = await fetch(`${API_BASE}/api/settings/diagnostics`, getRequestOptions());
    return res.json();
  },

  // Download URL builders (used for credentialed fetch downloads)
  getDownloadUrl(id, format) {
    return `${API_BASE}/api/reports/${id}/download?format=${format}`;
  },

  getWaptPdfUrl(id) {
    return `${API_BASE}/api/wapt/reports/${id}/pdf`;
  }
};
