/**
 * Evaluates the risk profile, grade, and statistical counts for a security scan.
 */

const SEVERITY_WEIGHTS = {
  'Critical': 10,
  'High': 7,
  'Medium': 4,
  'Low': 1
};

/**
 * Calculates security posture, grade, and distributions from findings.
 * @param {Array<any>} findings - Unified findings array.
 * @returns {any} Risk evaluation metrics object.
 */
function evaluateRisk(findings) {
  let penaltyPoints = 0;
  const severityCounts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0
  };

  const owaspCounts = {};
  const cweCounts = {};
  const fileCounts = {};

  findings.forEach(finding => {
    const sev = finding.severity || 'Medium';
    const weight = SEVERITY_WEIGHTS[sev] || 4;
    penaltyPoints += weight;

    // Count severities
    if (severityCounts[sev] !== undefined) {
      severityCounts[sev]++;
    } else {
      severityCounts[sev] = 1;
    }

    // Count OWASP
    if (finding.owasp) {
      owaspCounts[finding.owasp] = (owaspCounts[finding.owasp] || 0) + 1;
    }

    // Count CWE
    if (finding.cwe) {
      cweCounts[finding.cwe] = (cweCounts[finding.cwe] || 0) + 1;
    }

    // Count Files
    if (finding.path) {
      fileCounts[finding.path] = (fileCounts[finding.path] || 0) + 1;
    }
  });

  // Calculate Security Score (100 is perfect, 0 is worst)
  const securityScore = Math.max(0, 100 - penaltyPoints);

  // Assign Security Grade based on penalty points
  let grade = 'A';
  let rating = 'Secure';
  let gradeColor = '#10B981'; // Green

  if (penaltyPoints >= 80) {
    grade = 'F';
    rating = 'Critical Risk';
    gradeColor = '#EF4444'; // Red
  } else if (penaltyPoints >= 50) {
    grade = 'D';
    rating = 'High Risk';
    gradeColor = '#F59E0B'; // Orange
  } else if (penaltyPoints >= 25) {
    grade = 'C';
    rating = 'Medium Risk';
    gradeColor = '#FBBF24'; // Yellow
  } else if (penaltyPoints >= 10) {
    grade = 'B';
    rating = 'Low Risk';
    gradeColor = '#3B82F6'; // Blue
  }

  // Find most common issue category
  let topIssueCategory = 'None';
  let maxOwaspCount = 0;
  Object.entries(owaspCounts).forEach(([cat, count]) => {
    if (count > maxOwaspCount) {
      maxOwaspCount = count;
      topIssueCategory = cat.split('-')[0] || cat;
    }
  });

  return {
    penaltyPoints,
    securityScore,
    grade,
    rating,
    gradeColor,
    severityCounts,
    owaspCounts,
    cweCounts,
    fileCounts,
    topIssueCategory
  };
}

module.exports = {
  evaluateRisk
};
