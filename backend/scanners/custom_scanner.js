const fs = require('fs');
const path = require('path');

const CUSTOM_RULES = [
  {
    name: 'Debug Flag Enabled',
    regex: /(?:DEBUG|debug)\s*=\s*(?:True|true|1)\b/g,
    severity: 'Medium',
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-489',
    description: 'Active debug mode or flags found in code. Leaving debugging enabled in production environments can expose verbose stack traces, server internals, and interactive consoles to attackers.',
    remediation: 'Disable debug mode for production deployments. Drive configuration parameters through environment variables.',
    diffSuggest: (line) => `<<<< CURRENT CODE\n${line.trim()}\n==== SUGGESTED FIX\nconst debugMode = process.env.NODE_ENV !== 'production';\n>>>>`
  },
  {
    name: 'Sensitive Data Logging',
    regex: /(?:console\.(?:log|info|debug|warn)|logger\.(?:info|debug|warn|error))\s*\(\s*(?:.*?(?:password|passwd|secret|token|auth|key|credit|cvv).*?)\)/gi,
    severity: 'Medium',
    owasp: 'A09:2021-Security Logging and Monitoring Failures',
    cwe: 'CWE-532',
    description: 'Sensitive variables (like password, token, key) appear to be logged directly. This can leak credentials into log files, SIEM platforms, or console outputs.',
    remediation: 'Do not log sensitive variables. Redact or sanitize credentials before printing to console or log systems.',
    diffSuggest: (line) => `<<<< CURRENT CODE\n${line.trim()}\n==== SUGGESTED FIX\n// Redact sensitive details before logging\nlogger.info("Transaction processed for user " + userId);\n>>>>`
  },
  {
    name: 'Loose CORS Wildcard Policy',
    regex: /(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*['"]\*['"]/gi,
    severity: 'Medium',
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-942',
    description: 'CORS policy configured to allow any origin ("*"). This permits external domains to read response data from requests initiated by authenticated client browsers, enabling cross-site data exposure.',
    remediation: 'Explicitly define allowed origins rather than using a wildcard, or check origin dynamically against an allowlist.',
    diffSuggest: (line) => `<<<< CURRENT CODE\n${line.trim()}\n==== SUGGESTED FIX\nconst allowedOrigins = ['https://trusteddomain.com'];\n// Validate origins in CORS middleware\n>>>>`
  },
  {
    name: 'Insecure MD5/SHA-1 Hashing',
    regex: /\b(?:createHash|hash)\s*\(\s*['"](?:md5|sha1)['"]\s*\)/gi,
    severity: 'Low',
    owasp: 'A02:2021-Cryptographic Failures',
    cwe: 'CWE-328',
    description: 'Use of weak/broken cryptographic hash algorithms (MD5 or SHA-1). These algorithms are vulnerable to collision attacks and should not be used for integrity checks or sensitive data hashing.',
    remediation: 'Use secure modern hashing algorithms such as SHA-256 (e.g. `sha256`) or password-hashing schemes like bcrypt/argon2.',
    diffSuggest: (line) => `<<<< CURRENT CODE\n${line.trim()}\n==== SUGGESTED FIX\ncrypto.createHash('sha256');\n>>>>`
  },
  {
    name: 'Internal IP/Domain Leakage',
    // Match common internal IPv4 blocks (10.x.x.x, 192.168.x.x, 172.16.x.x to 172.31.x.x)
    regex: /\b(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/g,
    severity: 'Low',
    owasp: 'A01:2021-Broken Access Control',
    cwe: 'CWE-200',
    description: 'Internal IP address found hardcoded in source. While not a direct exploit, exposing internal network topologies aids attackers in mapping out lateral movement strategies within environments.',
    remediation: 'Avoid hardcoding internal networks. Externalize connection parameters into dynamic environment configs.',
    diffSuggest: (line) => `<<<< CURRENT CODE\n${line.trim()}\n==== SUGGESTED FIX\nconst internalServiceIp = process.env.INTERNAL_SERVICE_IP;\n>>>>`
  }
];

/**
 * Scans files for custom security and compliance issues.
 * @param {Array<{absolutePath: string, relativePath: string}>} files
 * @returns {Array<any>} List of custom findings.
 */
function scanCustomRules(files) {
  const findings = [];

  for (const file of files) {
    try {
      const stats = fs.statSync(file.absolutePath);
      if (stats.size > 1024 * 1024 * 5) continue; // Skip large files

      const content = fs.readFileSync(file.absolutePath, 'utf8');
      const lines = content.split(/\r?\n/);

      lines.forEach((lineText, lineIdx) => {
        CUSTOM_RULES.forEach(rule => {
          rule.regex.lastIndex = 0;
          let match;

          while ((match = rule.regex.exec(lineText)) !== null) {
            findings.push({
              id: `cust-${file.relativePath.replace(/[\/\.]/g, '-')}-${lineIdx + 1}-${match.index}`,
              rule_id: `custom-rule-${rule.name.toLowerCase().replace(/\s+/g, '-')}`,
              title: rule.name,
              severity: rule.severity,
              owasp: rule.owasp,
              cwe: rule.cwe,
              path: file.relativePath,
              line: lineIdx + 1,
              message: rule.description,
              codeSnippet: lineText.trim(),
              remediation: rule.remediation,
              suggestedDiff: rule.diffSuggest(lineText)
            });
          }
        });
      });
    } catch (e) {
      console.error(`Error in custom scanning of file ${file.relativePath}:`, e);
    }
  }

  return findings;
}

module.exports = {
  scanCustomRules
};
