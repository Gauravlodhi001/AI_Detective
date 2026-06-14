/* ==========================================================================
   AI-Detective Corporate Redesign - Centralized State Store
   ========================================================================== */

export const store = {
  state: {
    activeTab: 'scan',
    currentScanMode: 'zip',
    selectedFile: null,
    currentReport: null,
    severityChartInstance: null,
    owaspChartInstance: null,
    savedReports: [],
    
    // WAPT state
    waptActiveScanId: null,
    waptMultiRoleEnabled: false,
    waptConfigureRole: 'userA',
    
    // Multi-role authentication store
    waptAuthConfigs: {
      userA: { type: 'none', loginUrl: '', userField: 'email', pwdField: 'password', username: '', password: '', canaryUrl: '', headersJson: '' },
      userB: { type: 'none', loginUrl: '', userField: 'email', pwdField: 'password', username: '', password: '', canaryUrl: '', headersJson: '' },
      manager: { type: 'none', loginUrl: '', userField: 'email', pwdField: 'password', username: '', password: '', canaryUrl: '', headersJson: '' },
      admin: { type: 'none', loginUrl: '', userField: 'email', pwdField: 'password', username: '', password: '', canaryUrl: '', headersJson: '' }
    }
  },

  // State update actions
  set(key, value) {
    this.state[key] = value;
    this.notify(key, value);
  },

  setRoleConfig(role, field, value) {
    if (this.state.waptAuthConfigs[role]) {
      this.state.waptAuthConfigs[role][field] = value;
      this.notify(`waptAuthConfigs.${role}.${field}`, value);
    }
  },

  getRoleConfig(role) {
    return this.state.waptAuthConfigs[role] || null;
  },

  // Subscriber pattern for UI updates
  subscribers: {},

  subscribe(key, callback) {
    this.subscribers[key] = this.subscribers[key] || [];
    this.subscribers[key].push(callback);
  },

  notify(key, value) {
    if (this.subscribers[key]) {
      this.subscribers[key].forEach(cb => cb(value));
    }
    // Global notifications
    if (this.subscribers['*']) {
      this.subscribers['*'].forEach(cb => cb(key, value));
    }
  }
};
