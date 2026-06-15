const fs = require('fs');
const path = require('path');

const SECRET_PATTERNS = [
  {
    name: 'AWS Access Key ID',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    severity: 'Critical',
    owasp: 'A02:2021-Cryptographic Failures',
    cwe: 'CWE-798',
    description: 'A hardcoded AWS Access Key ID was detected. Anyone with access to this key can potentially make API calls to your AWS account.'
  },
  {
    name: 'AWS Secret Access Key',
    // Look for high-entropy 40-character Base64-like strings commonly labeled as secret keys
    regex: /(?<=aws_secret_access_key\s*[:=]\s*['"])[A-Za-z0-9/+=]{40}(?=['"])/gi,
    severity: 'Critical',
    owasp: 'A02:2021-Cryptographic Failures',
    cwe: 'CWE-798',
    description: 'A hardcoded AWS Secret Access Key was detected. Combined with an Access Key ID, this grants full programmatic access to AWS resources.'
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /gh[opru]_[a-zA-Z0-9]{36,255}/g,
    severity: 'High',
    owasp: 'A02:2021-Cryptographic Failures',
    cwe: 'CWE-798',
    description: 'A GitHub Personal Access Token (PAT) was detected. This can expose repository contents, organization access, or trigger actions.'
  },
  {
    name: 'Slack Webhook URL',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9_]+\/B[A-Z0-9_]+\/[A-Za-z0-9_]+/g,
    severity: 'High',
    owasp: 'A02:2021-Cryptographic Failures',
    cwe: 'CWE-522',
    description: 'A Slack Incoming Webhook URL was detected. Attackers could spam your Slack channels or steal incoming integration data.'
  },
  {
    name: 'Private Key Block',
    regex: /-----BEGIN (?:RSA|EC|DSA|GPG|OPENSSH)? PRIVATE KEY-----/g,
    severity: 'Critical',
    owasp: 'A02:2021-Cryptographic Failures',
    cwe: 'CWE-798',
    description: 'A private cryptographic key block was found hardcoded. This compromises secure transport (SSL/TLS) or authentication (SSH).'
  },
  {
    name: 'Generic API Key / Token',
    // Matches patterns like api_key = "...", token: "...", jwt_secret = '...'
    regex: /(?:api[-_]?key|secret|token|jwt[-_]?secret|db[-_]?pass|db[-_]?password|slack[-_]?token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,128})['"]/gi,
    severity: 'High',
    owasp: 'A02:2021-Cryptographic Failures',
    cwe: 'CWE-798',
    description: 'A likely hardcoded API key, token, or password was detected. Storing secrets in source code violates security best practices.',
    captureGroup: 1 // Extract only the token value itself for masking
  }
];

/**
 * Known placeholder/example values that commonly appear in documentation,
 * READMEs, SDK examples, and test fixtures. These are not real secrets and
 * should never be reported as findings, regardless of which target codebase
 * is being scanned.
 */
const KNOWN_PLACEHOLDER_SECRETS = new Set([
  'AKIAIOSFODNN7EXAMPLE',                          // AWS docs example Access Key ID
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'        // AWS docs example Secret Access Key
]);

/**
 * Masks a secret to protect it in reports while displaying the first/last characters.
 * Example: ghp_123456... -> ghp_12******56
 */
function maskSecret(secret) {
  if (secret.length <= 8) return '********';
  const prefixLen = Math.min(4, Math.floor(secret.length / 4));
  const suffixLen = Math.min(4, Math.floor(secret.length / 4));
  const prefix = secret.substring(0, prefixLen);
  const suffix = secret.substring(secret.length - suffixLen);
  return `${prefix}${'*'.repeat(secret.length - prefixLen - suffixLen)}${suffix}`;
}

/**
 * Scans a list of files for secrets.
 * @param {Array<{absolutePath: string, relativePath: string}>} files
 * @returns {Array<any>} List of secret findings.
 */
function scanSecrets(files) {
  const findings = [];

  for (const file of files) {
    try {
      // Avoid scanning extremely large files
      const stats = fs.statSync(file.absolutePath);
      if (stats.size > 1024 * 1024 * 5) continue; // Skip files > 5MB

      const content = fs.readFileSync(file.absolutePath, 'utf8');
      const lines = content.split(/\r?\n/);

      lines.forEach((lineText, lineIdx) => {
        SECRET_PATTERNS.forEach(pattern => {
          // Reset regex state
          pattern.regex.lastIndex = 0;
          let match;

          while ((match = pattern.regex.exec(lineText)) !== null) {
            const rawSecret = pattern.captureGroup !== undefined ? match[pattern.captureGroup] : match[0];

            // Skip known placeholder/example values (e.g. AWS docs' AKIAIOSFODNN7EXAMPLE)
            if (KNOWN_PLACEHOLDER_SECRETS.has(rawSecret)) continue;

            const maskedSecret = maskSecret(rawSecret);

            // Reconstruct a line snippet highlighting the match
            const startIdx = match.index;
            const endIdx = match.index + match[0].length;
            const displayLine = lineText.substring(0, startIdx) + `[SECRET_DETECTED]` + lineText.substring(endIdx);

            findings.push({
              id: `sec-${file.relativePath.replace(/[\/\.]/g, '-')}-${lineIdx + 1}-${startIdx}`,
              rule_id: `hardcoded-secret-${pattern.name.toLowerCase().replace(/\s+/g, '-')}`,
              title: `Hardcoded ${pattern.name}`,
              severity: pattern.severity,
              owasp: pattern.owasp,
              cwe: pattern.cwe,
              path: file.relativePath,
              line: lineIdx + 1,
              message: `${pattern.description} (Found: \`${maskedSecret}\`)`,
              codeSnippet: lineText.trim(),
              remediation: `Remove the hardcoded secret from your code. Store secrets in environment variables or use a secret management service (like HashiCorp Vault, AWS Secrets Manager, or dotenv files configured in .gitignore).`,
              suggestedDiff: `<<<< CURRENT CODE\n${lineText.trim()}\n==== SUGGESTED FIX\n// Read from environment variable or configuration service\nconst secretValue = process.env.API_KEY || "";\n>>>>`
            });
          }
        });
      });
    } catch (e) {
      console.error(`Error scanning secrets in file ${file.relativePath}:`, e);
    }
  }

  return findings;
}

module.exports = {
  scanSecrets
};
