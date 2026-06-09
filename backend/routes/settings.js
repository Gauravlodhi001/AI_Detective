const express = require('express');
const router = express.Router();
const { checkSemgrepInstalled } = require('../scanners/semgrep_scanner');
const { exec } = require('child_process');
const { getSemgrepEnv } = require('../scanners/semgrep_scanner'); // Actually it's not exported there, but we can call checkSemgrepInstalled or execute locally

/**
 * Helper to get version string of Semgrep if installed
 */
function getSemgrepVersion() {
  return new Promise((resolve) => {
    // We import from semgrep_scanner or run directly
    const { exec } = require('child_process');
    const path = require('path');
    const fs = require('fs');

    // Recreate scripts resolving environment
    const env = { ...process.env };
    let extraPaths = [];

    if (process.platform === 'win32') {
      const appData = process.env.APPDATA;
      if (appData) {
        const pythonBase = path.join(appData, 'Python');
        if (fs.existsSync(pythonBase)) {
          try {
            const subdirs = fs.readdirSync(pythonBase);
            subdirs.forEach(sub => {
              const scriptsPath = path.join(pythonBase, sub, 'Scripts');
              if (fs.existsSync(scriptsPath) && fs.existsSync(path.join(scriptsPath, 'semgrep.exe'))) {
                extraPaths.push(scriptsPath);
              }
            });
          } catch (e) {}
        }
      }
      const systemDrive = process.env.SystemDrive || 'C:';
      const pythonDirs = ['Python314', 'Python313', 'Python312', 'Python311', 'Python310', 'Python39'];
      pythonDirs.forEach(dir => {
        const scriptsPath = path.join(systemDrive, '\\', dir, 'Scripts');
        if (fs.existsSync(scriptsPath) && fs.existsSync(path.join(scriptsPath, 'semgrep.exe'))) {
          extraPaths.push(scriptsPath);
        }
      });
    }

    if (extraPaths.length > 0) {
      const delimiter = process.platform === 'win32' ? ';' : ':';
      env.PATH = extraPaths.join(delimiter) + delimiter + env.PATH;
    }

    exec('semgrep --version', { env }, (error, stdout) => {
      if (error) {
        resolve('Not Found / Inactive');
      } else {
        resolve(stdout.trim());
      }
    });
  });
}

/**
 * @route GET /api/settings/diagnostics
 * @desc Run environment diagnostics to detect tools
 */
router.get('/diagnostics', async (req, res, next) => {
  try {
    const isSemgrepInstalled = await checkSemgrepInstalled();
    const semgrepVersion = isSemgrepInstalled ? await getSemgrepVersion() : 'Not Found';

    res.json({
      success: true,
      diagnostics: {
        os: process.platform,
        nodeVersion: process.version,
        semgrepAvailable: isSemgrepInstalled,
        semgrepVersion: semgrepVersion,
        localTime: new Date().toISOString()
      }
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
