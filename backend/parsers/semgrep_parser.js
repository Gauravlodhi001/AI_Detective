const path = require('path');

/**
 * Maps Semgrep's severity string to our unified security severities (Critical, High, Medium, Low)
 */
function mapSeverity(semgrepSeverity, ruleId) {
  const sev = semgrepSeverity ? semgrepSeverity.toUpperCase() : 'WARNING';
  const idLower = (ruleId || '').toLowerCase();

  if (sev === 'ERROR') {
    // Escalate critical issues
    if (idLower.includes('sql-injection') || 
        idLower.includes('command-injection') || 
        idLower.includes('rce') || 
        idLower.includes('hardcoded-secret') ||
        idLower.includes('xxe') ||
        idLower.includes('deserialization')) {
      return 'Critical';
    }
    return 'High';
  } else if (sev === 'WARNING') {
    return 'Medium';
  } else {
    return 'Low';
  }
}

/**
 * Extracts and maps OWASP categories from Semgrep metadata
 */
function mapOwasp(metadata, ruleId) {
  const owaspList = metadata && metadata.owasp;
  if (Array.isArray(owaspList) && owaspList.length > 0) {
    return owaspList[0];
  } else if (typeof owaspList === 'string') {
    return owaspList;
  }

  // Fallback heuristic based on rule naming
  const idLower = (ruleId || '').toLowerCase();
  if (idLower.includes('sqli') || idLower.includes('injection') || idLower.includes('xxe')) {
    return 'A03:2021-Injection';
  }
  if (idLower.includes('auth') || idLower.includes('jwt') || idLower.includes('session')) {
    return 'A07:2021-Identification and Authentication Failures';
  }
  if (idLower.includes('crypto') || idLower.includes('secret') || idLower.includes('password') || idLower.includes('hash')) {
    return 'A02:2021-Cryptographic Failures';
  }
  if (idLower.includes('xss') || idLower.includes('html') || idLower.includes('csrf')) {
    return 'A03:2021-Injection'; // Or specific A03/A01 depending on standard
  }
  if (idLower.includes('path-traversal') || idLower.includes('directory-traversal') || idLower.includes('acl')) {
    return 'A01:2021-Broken Access Control';
  }
  
  return 'A05:2021-Security Misconfiguration'; // Default fallback
}

/**
 * Extracts CWE mappings from Semgrep metadata
 */
function mapCwe(metadata, ruleId) {
  const cweList = metadata && metadata.cwe;
  if (Array.isArray(cweList) && cweList.length > 0) {
    const cweStr = cweList[0];
    const match = cweStr.match(/CWE-\d+/i);
    return match ? match[0].toUpperCase() : 'CWE-200';
  } else if (typeof cweList === 'string') {
    const match = cweList.match(/CWE-\d+/i);
    return match ? match[0].toUpperCase() : 'CWE-200';
  }

  // Fallback heuristic
  const idLower = (ruleId || '').toLowerCase();
  if (idLower.includes('sqli') || idLower.includes('sql-injection')) return 'CWE-89';
  if (idLower.includes('xss') || idLower.includes('cross-site-scripting')) return 'CWE-79';
  if (idLower.includes('secret') || idLower.includes('key')) return 'CWE-798';
  if (idLower.includes('command-injection') || idLower.includes('exec')) return 'CWE-78';
  if (idLower.includes('path-traversal')) return 'CWE-22';
  if (idLower.includes('csrf')) return 'CWE-352';
  if (idLower.includes('xxe')) return 'CWE-611';

  return 'CWE-200'; // General Information Exposure
}

/**
 * Generates an educational code diff showing how to fix common vulnerabilities
 */
function generateFixDiff(ruleId, originalCode, message) {
  const cleanCode = (originalCode || '').trim();
  const idLower = (ruleId || '').toLowerCase();

  if (idLower.includes('sql-injection') || idLower.includes('sqli')) {
    return `<<<< CURRENT CODE\n// Vulnerable string-concatenated SQL query\nquery = "SELECT * FROM users WHERE id = '" + req.query.id + "'";\ndb.execute(query);\n==== SUGGESTED FIX\n// Use parameterized/prepared queries to prevent SQL Injection\nquery = "SELECT * FROM users WHERE id = ?";\ndb.execute(query, [req.query.id]);\n>>>>`;
  }

  if (idLower.includes('xss') || idLower.includes('innerhtml') || idLower.includes('dangerouslysetinnerhtml')) {
    return `<<<< CURRENT CODE\n// Vulnerable: raw user input in innerHTML\nelement.innerHTML = userInput;\n==== SUGGESTED FIX\n// Use textContent for plain text, or a sanitization library (DOMPurify)\nelement.textContent = userInput;\n>>>>`;
  }

  if (idLower.includes('exec') || idLower.includes('command-injection') || idLower.includes('subprocess')) {
    return `<<<< CURRENT CODE\n// Vulnerable: exec shell with direct string interpolation\nexec(\`ping -c 1 \${host}\`);\n==== SUGGESTED FIX\n// Use execFile, or validate parameters against allowlists\nexecFile('/bin/ping', ['-c', '1', host], (error, stdout) => {\n  // Handle result safely\n});\n>>>>`;
  }

  if (idLower.includes('eval')) {
    return `<<<< CURRENT CODE\n// Vulnerable: eval() execution of dynamic strings\neval(userInput);\n==== SUGGESTED FIX\n// Use JSON.parse or strict map lookups instead of dynamic code\nconst data = JSON.parse(userInput);\n>>>>`;
  }

  if (idLower.includes('path-traversal') || idLower.includes('traversal')) {
    return `<<<< CURRENT CODE\n// Vulnerable: raw filename concatenations\nconst filePath = path.join(uploadDir, req.query.filename);\n==== SUGGESTED FIX\n// Sanitize name and resolve against root folder boundaries\nconst safeName = path.basename(req.query.filename);\nconst filePath = path.resolve(uploadDir, safeName);\nif (!filePath.startsWith(path.resolve(uploadDir))) {\n  throw new Error("Access Denied");\n}\n>>>>`;
  }

  // Generic fallback diff block
  return `<<<< CURRENT CODE\n${cleanCode}\n==== SUGGESTED FIX\n// Review standard mitigation guidelines for ${ruleId}.\n// Sanitize input, restrict access controls, or apply configuration limits.\n>>>>`;
}

/**
 * Transforms Semgrep JSON results array into unified report findings
 * @param {any} semgrepJson - Raw Semgrep output object.
 * @param {string} relativeScanDir - Relative folder context.
 * @returns {Array<any>} List of formatted findings.
 */
function parseSemgrepResults(semgrepJson, relativeScanDir) {
  if (!semgrepJson || !Array.isArray(semgrepJson.results)) {
    return [];
  }

  return semgrepJson.results.map((item, index) => {
    const ruleId = item.check_id || 'semgrep-rule';
    const filePath = item.path || '';
    const line = item.start ? item.start.line : 1;
    const severity = mapSeverity(item.extra ? item.extra.severity : 'WARNING', ruleId);
    const owasp = mapOwasp(item.extra ? item.extra.metadata : null, ruleId);
    const cwe = mapCwe(item.extra ? item.extra.metadata : null, ruleId);
    const message = item.extra ? item.extra.message : 'Security issue found by static analysis.';
    const originalCode = item.extra ? item.extra.lines : '';
    const title = ruleId.split('.').pop().replace(/[-_]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

    const cweDetails = item.extra && item.extra.metadata && item.extra.metadata.cwe
      ? (Array.isArray(item.extra.metadata.cwe) ? item.extra.metadata.cwe[0] : item.extra.metadata.cwe)
      : '';
    const cweLabel = cweDetails ? ` (${cweDetails.split(':')[1] || ''})` : '';

    return {
      id: `sem-${ruleId.replace(/[\/\.]/g, '-')}-${index}-${line}`,
      rule_id: ruleId,
      title: title,
      severity: severity,
      owasp: owasp,
      cwe: cwe,
      path: filePath,
      line: line,
      message: message,
      codeSnippet: originalCode.trim(),
      remediation: item.extra && item.extra.metadata && item.extra.metadata.remediation
        ? item.extra.metadata.remediation
        : `Implement sanitization/validation on input parameters. Restrict function permissions or update vulnerable implementation blocks.`,
      suggestedDiff: generateFixDiff(ruleId, originalCode, message)
    };
  });
}

module.exports = {
  parseSemgrepResults
};
