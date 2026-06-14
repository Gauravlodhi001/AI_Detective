/* ==========================================================================
   AI-Detective Corporate Redesign - API Client Wrapper
   ========================================================================== */

const API_BASE = window.location.origin;

export const api = {
  // SAST & Code Reports
  async getReportsList() {
    const res = await fetch(`${API_BASE}/api/reports/list`);
    return res.json();
  },

  async getReport(id) {
    const res = await fetch(`${API_BASE}/api/reports/${id}`);
    if (res.status === 404) throw new Error('Report not found');
    return res.json();
  },

  async deleteReport(id) {
    const res = await fetch(`${API_BASE}/api/reports/${id}`, { method: 'DELETE' });
    return res.json();
  },

  async runZipScan(formData) {
    const res = await fetch(`${API_BASE}/api/scan/upload`, {
      method: 'POST',
      body: formData
    });
    return res.json();
  },

  async runGitScan(gitUrl, branch) {
    const res = await fetch(`${API_BASE}/api/scan/git`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ gitUrl, branch })
    });
    return res.json();
  },

  async runPasteScan(code, filename, projectName) {
    const res = await fetch(`${API_BASE}/api/scan/paste`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, filename, projectName })
    });
    return res.json();
  },

  async launchAiAudit(id) {
    const res = await fetch(`${API_BASE}/api/scan/${id}/ai-analyze`, { method: 'POST' });
    return res.json();
  },

  // WAPT & Dynamic Assessments
  async triggerWaptScan(targetUrl, authConfig, scanId) {
    const res = await fetch(`${API_BASE}/api/wapt/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ targetUrl, authConfig, scanId })
    });
    return res.json();
  },

  async getWaptLogs(scanId) {
    const res = await fetch(`${API_BASE}/api/wapt/scan/${scanId}/logs`);
    return res.json();
  },

  async getWaptReports() {
    const res = await fetch(`${API_BASE}/api/wapt/reports`);
    return res.json();
  },

  async getWaptReportDetails(id) {
    const res = await fetch(`${API_BASE}/api/wapt/reports/${id}`);
    if (res.status === 404) throw new Error('WAPT report not found');
    return res.json();
  },

  async getWaptBenchmarks() {
    const res = await fetch(`${API_BASE}/api/wapt/benchmark`);
    return res.json();
  },

  // Settings & Diagnostics
  async getDiagnostics() {
    const res = await fetch(`${API_BASE}/api/settings/diagnostics`);
    return res.json();
  },

  // Download links helpers
  getDownloadUrl(id, format) {
    return `${API_BASE}/api/reports/${id}/download?format=${format}`;
  },

  getWaptPdfUrl(id) {
    return `${API_BASE}/api/wapt/reports/${id}/pdf`;
  }
};
