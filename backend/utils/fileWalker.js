const fs = require('fs');
const path = require('path');

// Excluded directories and file patterns to avoid performance bottlenecks and false positives
const EXCLUDED_DIRS = new Set([
  'node_modules',
  '.git',
  '.github',
  'dist',
  'build',
  'venv',
  'env',
  '.env',
  '__pycache__',
  '.idea',
  '.vscode',
  'out',
  'target',
  'bin',
  'obj'
]);

const EXCLUDED_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg',
  '.pdf', '.zip', '.tar', '.gz', '.rar',
  '.exe', '.dll', '.so', '.dylib', '.bin',
  '.woff', '.woff2', '.eot', '.ttf',
  '.mp4', '.mp3', '.wav', '.avi', '.mov',
  '.db', '.sqlite', '.sqlite3',
  '.png', '.webp', '.lock'
]);

/**
 * Recursively walks a directory and lists all code/configuration files.
 * @param {string} dirPath - Absolute path of directory to walk.
 * @param {string} baseDir - Base directory path to generate relative paths.
 * @param {Array<string>} fileList - Accumulated list of files (used in recursion).
 * @returns {Array<{absolutePath: string, relativePath: string, extension: string}>} List of files.
 */
function walkDir(dirPath, baseDir = dirPath, fileList = []) {
  if (!fs.existsSync(dirPath)) return fileList;

  const items = fs.readdirSync(dirPath, { withFileTypes: true });

  for (const item of items) {
    const itemName = item.name;
    const absolutePath = path.join(dirPath, itemName);
    const relativePath = path.relative(baseDir, absolutePath).replace(/\\/g, '/');

    if (item.isDirectory()) {
      if (!EXCLUDED_DIRS.has(itemName)) {
        walkDir(absolutePath, baseDir, fileList);
      }
    } else if (item.isFile()) {
      const ext = path.extname(itemName).toLowerCase();
      // Only include text-based and configuration/manifest files
      if (!EXCLUDED_EXTENSIONS.has(ext)) {
        fileList.push({
          absolutePath,
          relativePath,
          extension: ext
        });
      }
    }
  }

  return fileList;
}

module.exports = {
  walkDir
};
