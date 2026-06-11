class RbacAuditor {
  constructor(log) {
    this.log = log || [];
  }

  // Audits an endpoint against all 5 roles and returns matrix results
  async auditEndpoint(endpoint, sessions, requestFn) {
    const { path, fullUrl, method } = endpoint;
    this.log.push(`[RBACAuditor] Auditing: ${method} ${fullUrl}`);

    const matrixRow = {
      path,
      method,
      guest: null,
      userA: null,
      userB: null,
      manager: null,
      admin: null,
      isVulnerable: false,
      escalations: []
    };

    const roles = ['guest', 'userA', 'userB', 'manager', 'admin'];

    for (const role of roles) {
      const session = sessions[role];
      const headers = session ? session.getHeaders() : {};

      try {
        const res = await requestFn(fullUrl, {
          method,
          headers
        });
        matrixRow[role] = res.status;
      } catch (err) {
        this.log.push(`[RBACAuditor] Error testing role ${role} on ${method} ${path}: ${err.message}`);
        matrixRow[role] = 500;
      }
    }

    // Run privilege checks
    this.evaluateMatrixRules(matrixRow);

    return matrixRow;
  }

  evaluateMatrixRules(row) {
    const isSuccess = (status) => status >= 200 && status < 300;
    
    // Rule 1: Vertical Privilege Escalation to Admin
    // If route contains admin keywords or is only expected for Admins, and non-admin gets 2xx
    const isAdminRoute = row.path.toLowerCase().includes('/admin') || row.path.toLowerCase().includes('/manager');
    
    if (isAdminRoute) {
      if (isSuccess(row.guest)) {
        row.isVulnerable = true;
        row.escalations.push(`Unauthenticated Guest bypass on Admin route: ${row.method} ${row.path}`);
      }
      if (isSuccess(row.userA)) {
        row.isVulnerable = true;
        row.escalations.push(`Standard User A privilege escalation on Admin route: ${row.method} ${row.path}`);
      }
      if (isSuccess(row.userB)) {
        row.isVulnerable = true;
        row.escalations.push(`Standard User B privilege escalation on Admin route: ${row.method} ${row.path}`);
      }
      if (row.path.toLowerCase().includes('/admin') && isSuccess(row.manager)) {
        row.isVulnerable = true;
        row.escalations.push(`Manager privilege escalation on Admin route: ${row.method} ${row.path}`);
      }
    }

    // Rule 2: Broken Function Level Authorization
    // If a POST/DELETE/PUT endpoint is successful for Guests or Standard Users
    const isSensitiveMethod = ['POST', 'DELETE', 'PUT', 'PATCH'].includes(row.method.toUpperCase());
    if (isSensitiveMethod && !isAdminRoute) {
      if (isSuccess(row.guest)) {
        row.isVulnerable = true;
        row.escalations.push(`Missing authentication on sensitive state-changing action: ${row.method} ${row.path}`);
      }
      // If User A can perform a sensitive action that only Manager/Admin should do
      if (row.path.toLowerCase().includes('/manage') || row.path.toLowerCase().includes('/settings')) {
        if (isSuccess(row.userA) || isSuccess(row.userB)) {
          row.isVulnerable = true;
          row.escalations.push(`Standard user executed management action: ${row.method} ${row.path}`);
        }
      }
    }
  }

  // Audits all endpoints across all roles
  async runAudit(endpoints, sessions, requestFn) {
    this.log.push(`[RBACAuditor] Starting multi-role RBAC matrix audit across ${endpoints.length} endpoints.`);
    const matrix = [];
    
    for (const endpoint of endpoints) {
      const row = await this.auditEndpoint(endpoint, sessions, requestFn);
      matrix.push(row);
    }
    
    this.log.push(`[RBACAuditor] RBAC audit complete. Evaluated ${matrix.length} routes.`);
    return matrix;
  }
}

module.exports = { RbacAuditor };
