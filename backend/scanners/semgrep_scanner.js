const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

/**
 * Resolves the path to the semgrep executable on the host system.
 * On Windows, Python packages might be installed under %APPDATA%\Python\PythonXX\Scripts.
 * We scan that directory to automatically prepend the script paths.
 */
function getSemgrepEnv() {
  const env = { ...process.env };
  
  // Start with current PATH
  let extraPaths = [];

  if (process.platform === 'win32') {
    // 1. Check standard %APPDATA%\Python path
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
        } catch (e) {
          console.error('Error walking python base dir:', e);
        }
      }
    }

    // 2. Add common Python install locations
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

  return env;
}

/**
 * Checks if Semgrep is installed and available.
 * @returns {Promise<boolean>}
 */
function checkSemgrepInstalled() {
  return new Promise((resolve) => {
    const env = getSemgrepEnv();
    exec('semgrep --version', { env }, (error, stdout) => {
      if (error) {
        resolve(false);
      } else {
        resolve(true);
      }
    });
  });
}

/**
 * Runs a Semgrep scan on the target directory and returns the JSON output.
 * @param {string} targetDir - Path of directory to scan.
 * @returns {Promise<{success: boolean, data?: any, error?: string}>}
 */
function runSemgrepScan(targetDir) {
  return new Promise((resolve) => {
    const env = getSemgrepEnv();
    // --config auto tells semgrep to use auto-discovered registry rules
    // --json prints outputs in JSON format
    const command = `semgrep scan --config auto --json "${targetDir}"`;

    console.log(`Executing Semgrep: ${command}`);

    // Increase maxBuffer to 50MB to support large output JSONs
    exec(command, { env, maxBuffer: 1024 * 1024 * 50 }, (error, stdout, stderr) => {
      // Note: Semgrep exits with non-zero code if it finds vulnerabilities,
      // so we shouldn't necessarily reject just because error is present.
      // We check if we got valid JSON stdout first.
      if (stdout) {
        try {
          const jsonResult = JSON.parse(stdout);
          return resolve({
            success: true,
            data: jsonResult
          });
        } catch (parseErr) {
          console.error('Failed to parse Semgrep JSON output:', parseErr);
        }
      }

      if (error && !stdout) {
        console.error(`Semgrep execution error: ${error.message}`);
        return resolve({
          success: false,
          error: error.message || stderr || 'Semgrep failed to execute.'
        });
      }

      resolve({
        success: false,
        error: 'No output received from Semgrep'
      });
    });
  });
}

module.exports = {
  checkSemgrepInstalled,
  runSemgrepScan
};
