const path = require('path');
const { buildReport } = require('./backend/parsers/report_builder');

async function testScan() {
  console.log('Starting automated scanner verification test...');
  
  const targetDir = path.join(__dirname, 'test-vulnerable-project');
  
  try {
    const report = await buildReport(targetDir, 'Verification Test Project');
    
    console.log('\n--- SCAN VERIFICATION RESULTS ---');
    console.log(`Project Name: ${report.projectName}`);
    console.log(`Scan Date: ${report.scanTime}`);
    console.log(`Files Audited: ${report.filesScannedCount}`);
    console.log(`Semgrep Status: ${report.semgrepStatus}`);
    
    const m = report.metrics;
    console.log(`Overall Grade: ${m.grade} (${m.rating})`);
    console.log(`Security Score: ${m.securityScore}/100`);
    console.log(`Total Findings: ${report.findings.length}`);
    
    console.log('\nFindings Breakdown:');
    console.log(`- Critical: ${m.severityCounts.Critical}`);
    console.log(`- High: ${m.severityCounts.High}`);
    console.log(`- Medium: ${m.severityCounts.Medium}`);
    console.log(`- Low: ${m.severityCounts.Low}`);
    
    if (report.findings.length > 0) {
      console.log('\nSample Findings:');
      report.findings.slice(0, 5).forEach((f, index) => {
        console.log(`[${index + 1}] Severity: ${f.severity} | Title: ${f.title} | File: ${f.path}:${f.line}`);
      });
      
      console.log('\nValidation Succeeded! The hybrid scanning engine is functioning properly.');
      process.exit(0);
    } else {
      console.error('\nValidation Failed: No vulnerabilities were detected in the test project.');
      process.exit(1);
    }

  } catch (err) {
    console.error('Scan verification crashed with error:', err);
    process.exit(1);
  }
}

testScan();
