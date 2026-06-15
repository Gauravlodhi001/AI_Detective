const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');
const { URL } = require('url');

/**
 * Parses the repository name from a Git URL.
 * Example: https://github.com/expressjs/express.git -> express
 */
function getRepoName(gitUrl) {
  try {
    const url = gitUrl.trim();
    const parts = url.split('/');
    let lastPart = parts[parts.length - 1];
    if (lastPart.endsWith('.git')) {
      lastPart = lastPart.substring(0, lastPart.length - 4);
    }
    return lastPart || 'cloned-repo';
  } catch (e) {
    return 'cloned-repo';
  }
}

/**
 * Clones a git repository into a target directory.
 * @param {string} gitUrl - The remote Git URL to clone.
 * @param {string} targetDir - Absolute destination directory.
 * @returns {Promise<{success: boolean, error?: string, repoName: string}>}
 */
function cloneRepo(gitUrl, targetDir) {
  return new Promise((resolve) => {
    const repoName = getRepoName(gitUrl);
    
    // Validate gitUrl protocol
    try {
      const parsedUrl = new URL(gitUrl.trim());
      if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
        return resolve({
          success: false,
          error: 'Only HTTP and HTTPS protocols are allowed for git URL cloning.',
          repoName
        });
      }
    } catch (err) {
      return resolve({
        success: false,
        error: 'Invalid Git repository URL structure.',
        repoName
      });
    }

    // Clean target directory if it somehow exists
    if (fs.existsSync(targetDir)) {
      try {
        fs.rmSync(targetDir, { recursive: true, force: true });
      } catch (rmErr) {
        console.error(`Error clearing target directory: ${rmErr.message}`);
      }
    }

    console.log(`Executing safe git clone for: ${gitUrl}`);

    // Set timeout to 2 minutes (120000ms) to prevent hanging on credentials prompts or huge repos
    execFile('git', ['clone', '--depth', '1', gitUrl.trim(), targetDir], { timeout: 120000 }, (error, stdout, stderr) => {
      if (error) {
        console.error(`Git clone failed: ${error.message}`);
        return resolve({
          success: false,
          error: error.message || stderr || 'Failed to clone the Git repository. Ensure the URL is correct and public.',
          repoName
        });
      }
      
      resolve({
        success: true,
        repoName
      });
    });
  });
}

module.exports = {
  cloneRepo,
  getRepoName
};
