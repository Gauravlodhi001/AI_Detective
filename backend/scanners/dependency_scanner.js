const fs = require('fs');
const path = require('path');

// Local database of known vulnerable packages and their maximum vulnerable versions (exclusive limit)
const VULN_DATABASE = {
  npm: {
    'lodash': {
      maxVulnerable: '4.17.21',
      cve: 'CVE-2021-23337',
      severity: 'High',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cwe: 'CWE-1395',
      description: 'Prototype pollution in lodash allows remote attackers to inject properties onto Object.prototype via merge/zipObject/defaultsDeep functions.',
      fix: 'Upgrade lodash to 4.17.21 or higher.'
    },
    'express': {
      maxVulnerable: '4.19.2',
      cve: 'CVE-2024-43796',
      severity: 'High',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cwe: 'CWE-1395',
      description: 'Express open redirect vulnerability in redirect responses where paths are improperly parsed and lead to phishing/redirection attacks.',
      fix: 'Upgrade express to 4.19.2 or higher.'
    },
    'axios': {
      maxVulnerable: '1.6.0',
      cve: 'CVE-2023-45857',
      severity: 'Medium',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cwe: 'CWE-1395',
      description: 'Server-Side Request Forgery (SSRF) vulnerability in axios when handling request host configuration headers during redirects.',
      fix: 'Upgrade axios to 1.6.0 or higher.'
    },
    'moment': {
      maxVulnerable: '2.29.4',
      cve: 'CVE-2022-31129',
      severity: 'Medium',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cwe: 'CWE-1395',
      description: 'Regular Expression Denial of Service (ReDoS) vulnerability in moment when parsing specific malformed date string formats.',
      fix: 'Upgrade moment to 2.29.4 or higher.'
    },
    'jsonwebtoken': {
      maxVulnerable: '9.0.0',
      cve: 'CVE-2022-25883',
      severity: 'High',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cwe: 'CWE-1395',
      description: 'Verification bypass vulnerability when verifying token signatures due to improper handling of key types.',
      fix: 'Upgrade jsonwebtoken to 9.0.0 or higher.'
    }
  },
  pip: {
    'requests': {
      maxVulnerable: '2.31.0',
      cve: 'CVE-2023-32681',
      severity: 'Medium',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cwe: 'CWE-1395',
      description: 'Requests leaks Authorization headers on cross-origin redirects, potentially exposing API tokens to untrusted third-party sites.',
      fix: 'Upgrade requests to 2.31.0 or higher.'
    },
    'django': {
      maxVulnerable: '4.2.10',
      cve: 'CVE-2024-27351',
      severity: 'High',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cwe: 'CWE-1395',
      description: 'Django regular expression denial of service (ReDoS) in django.utils.text.Truncator when processing lengthy texts.',
      fix: 'Upgrade django to 4.2.10 or higher.'
    },
    'flask': {
      maxVulnerable: '2.3.2',
      cve: 'CVE-2023-30861',
      severity: 'High',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cwe: 'CWE-1395',
      description: 'Flask cookies signed with default keys are decryptable, leading to session hijacking or cookie tampering.',
      fix: 'Upgrade flask to 2.3.2 or higher.'
    },
    'urllib3': {
      maxVulnerable: '1.26.17',
      cve: 'CVE-2023-43804',
      severity: 'High',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cwe: 'CWE-1395',
      description: 'Urllib3 leaks Authorization headers on redirect to a different host, exposing critical session tokens.',
      fix: 'Upgrade urllib3 to 1.26.17 or higher.'
    },
    'cryptography': {
      maxVulnerable: '41.0.6',
      cve: 'CVE-2023-49083',
      severity: 'High',
      owasp: 'A06:2021-Vulnerable and Outdated Components',
      cwe: 'CWE-1395',
      description: 'Improper parsing of certain X.509 certificates leads to a NULL pointer dereference, causing denial of service.',
      fix: 'Upgrade cryptography to 41.0.6 or higher.'
    }
  }
};

/**
 * Compares two semver version strings (e.g., '1.2.3' and '1.3.0').
 * Returns true if versionA is strictly less than versionB.
 */
function semverLessThan(versionA, versionB) {
  const partsA = versionA.split('.').map(x => parseInt(x, 10) || 0);
  const partsB = versionB.split('.').map(x => parseInt(x, 10) || 0);

  for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
    const a = partsA[i] || 0;
    const b = partsB[i] || 0;
    if (a < b) return true;
    if (a > b) return false;
  }
  return false; // Equal
}

/**
 * Cleans a version string (removes leading ^, ~, >=, <=, etc.)
 */
function cleanVersion(versionStr) {
  if (!versionStr) return '0.0.0';
  return versionStr.replace(/^[\^~>=<=\s]+/, '').split(/\s/)[0].trim();
}

/**
 * Scans project manifests (like package.json or requirements.txt) for outdated/vulnerable libraries.
 * @param {Array<{absolutePath: string, relativePath: string}>} files
 * @returns {Array<any>} List of dependency findings.
 */
function scanDependencies(files) {
  const findings = [];

  for (const file of files) {
    const filename = path.basename(file.absolutePath);

    if (filename === 'package.json') {
      try {
        const content = fs.readFileSync(file.absolutePath, 'utf8');
        const packageJson = JSON.parse(content);
        const dependencies = {
          ...(packageJson.dependencies || {}),
          ...(packageJson.devDependencies || {})
        };

        Object.entries(dependencies).forEach(([pkg, versionRange]) => {
          const vulnInfo = VULN_DATABASE.npm[pkg];
          if (vulnInfo) {
            const currentVer = cleanVersion(versionRange);
            if (semverLessThan(currentVer, vulnInfo.maxVulnerable)) {
              findings.push({
                id: `dep-npm-${pkg}-${currentVer}`,
                rule_id: `outdated-package-${pkg}`,
                title: `Vulnerable Dependency: ${pkg}`,
                severity: vulnInfo.severity,
                owasp: vulnInfo.owasp,
                cwe: vulnInfo.cwe,
                cve: vulnInfo.cve,
                path: file.relativePath,
                line: 1, // Default manifest level
                message: `Manifest references ${pkg}@${currentVer} which contains a known vulnerability (${vulnInfo.cve}).\nDescription: ${vulnInfo.description}`,
                codeSnippet: `"${pkg}": "${versionRange}"`,
                remediation: vulnInfo.fix,
                suggestedDiff: `<<<< CURRENT CODE\n"${pkg}": "${versionRange}"\n==== SUGGESTED FIX\n"${pkg}": "^${vulnInfo.maxVulnerable}"\n>>>>`
              });
            }
          }
        });
      } catch (err) {
        console.error('Error parsing package.json:', err);
      }
    } else if (filename === 'requirements.txt') {
      try {
        const content = fs.readFileSync(file.absolutePath, 'utf8');
        const lines = content.split(/\r?\n/);

        lines.forEach((lineText, lineIdx) => {
          const cleaned = lineText.trim();
          if (!cleaned || cleaned.startsWith('#')) return;

          // Parse name and version, e.g. requests==2.28.1 or flask>=2.0,<2.3
          const match = cleaned.match(/^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|~=|>|<)\s*([0-9\.]+)/);
          if (match) {
            const pkg = match[1].toLowerCase();
            const version = match[2];
            const vulnInfo = VULN_DATABASE.pip[pkg];

            if (vulnInfo) {
              const currentVer = cleanVersion(version);
              if (semverLessThan(currentVer, vulnInfo.maxVulnerable)) {
                findings.push({
                  id: `dep-pip-${pkg}-${lineIdx + 1}`,
                  rule_id: `outdated-package-${pkg}`,
                  title: `Vulnerable Dependency: ${pkg}`,
                  severity: vulnInfo.severity,
                  owasp: vulnInfo.owasp,
                  cwe: vulnInfo.cwe,
                  cve: vulnInfo.cve,
                  path: file.relativePath,
                  line: lineIdx + 1,
                  message: `Manifest references ${pkg}@${currentVer} which contains a known vulnerability (${vulnInfo.cve}).\nDescription: ${vulnInfo.description}`,
                  codeSnippet: cleaned,
                  remediation: vulnInfo.fix,
                  suggestedDiff: `<<<< CURRENT CODE\n${cleaned}\n==== SUGGESTED FIX\n${pkg}==${vulnInfo.maxVulnerable}\n>>>>`
                });
              }
            }
          }
        });
      } catch (err) {
        console.error('Error parsing requirements.txt:', err);
      }
    }
  }

  return findings;
}

module.exports = {
  scanDependencies
};
