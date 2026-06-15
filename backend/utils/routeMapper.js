const fs = require('fs');
const path = require('path');

/**
 * Robust static parser to extract route-to-code mapping from Express Node.js applications.
 */
class RouteMapper {
  constructor(log) {
    this.log = log || [];
    this.routes = []; // Array of { path, method, routerFile, controllerFile, handlerFunction, lineStart, lineEnd }
  }

  // Recursively walks directory to find all JavaScript files
  getFileList(dir, fileList = []) {
    if (!fs.existsSync(dir)) return fileList;
    const files = fs.readdirSync(dir);
    for (const file of files) {
      const filePath = path.join(dir, file);
      // Skip node_modules, .git, cloned_repos, uploads, reports
      if (file === 'node_modules' || file === '.git' || file === 'cloned_repos' || file === 'uploads' || file === 'reports' || file === 'scratch') {
        continue;
      }
      const stat = fs.statSync(filePath);
      if (stat.isDirectory()) {
        this.getFileList(filePath, fileList);
      } else if (filePath.endsWith('.js')) {
        fileList.push(filePath);
      }
    }
    return fileList;
  }

  // Resolves relative require paths to absolute files
  resolveRequirePath(currentFile, requirePath) {
    try {
      const currentDir = path.dirname(currentFile);
      let resolved = path.resolve(currentDir, requirePath);
      if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
        return resolved;
      }
      if (fs.existsSync(resolved + '.js')) {
        return resolved + '.js';
      }
      if (fs.existsSync(path.join(resolved, 'index.js'))) {
        return path.join(resolved, 'index.js');
      }
    } catch (e) {}
    return null;
  }

  // Scans a single Javascript file for Express routes and maps them to controllers
  scanFile(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      // 1. Extract imports and requires mapping (e.g. const controller = require('./controller'))
      const requireMap = {}; // Maps prefix or destructured name -> absolute controller file path
      const requireRegex = /(?:const|let|var)\s+([\w\s{},]+)\s*=\s*require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g;
      let reqMatch;
      while ((reqMatch = requireRegex.exec(content)) !== null) {
        const importBlock = reqMatch[1].trim();
        const reqPath = reqMatch[2];
        const resolvedPath = this.resolveRequirePath(filePath, reqPath);
        if (!resolvedPath) continue;

        if (importBlock.startsWith('{') && importBlock.endsWith('}')) {
          // Destructured require: const { getVal, setVal } = require('./file')
          const vars = importBlock.slice(1, -1).split(',').map(v => v.trim());
          vars.forEach(v => {
            // Support "a as b" or renaming if present, though rare in Node.js requires
            const name = v.split(/\s+as\s+/)[0].trim();
            if (name) requireMap[name] = resolvedPath;
          });
        } else {
          // Direct require: const userController = require('./controller')
          requireMap[importBlock] = resolvedPath;
        }
      }

      // 2. Scan for route registrations
      // Matches: router.get('/users', auth, userController.getUser) or app.post('/login', login)
      // Also handles inline functions like router.get('/hello', (req,res) => {})
      const routeRegex = /\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`\s]+)['"`]\s*,\s*(?:[\w.]+\s*,\s*)*([\w.()=>\s{]+)/gi;
      let routeMatch;
      while ((routeMatch = routeRegex.exec(content)) !== null) {
        const method = routeMatch[1].toUpperCase();
        const routePath = routeMatch[2];
        let handlerRaw = routeMatch[3].trim();

        // Get line number of route definition
        const index = routeMatch.index;
        const lineStart = content.substring(0, index).split('\n').length;

        // Clean up handler parameter (if it includes closing brackets or callback body)
        if (handlerRaw.includes('(') || handlerRaw.includes('=>') || handlerRaw.includes('{')) {
          // Inline handler: router.get('/path', (req, res) => { ... })
          this.routes.push({
            path: routePath,
            method,
            routerFile: filePath,
            controllerFile: filePath,
            handlerFunction: 'inline',
            lineStart,
            lineEnd: lineStart + 5 // Approximate inline range
          });
        } else {
          // Standard controller reference: userController.createUser or createUser
          let handlerName = handlerRaw.split(',')[0].split(')')[0].trim();
          let controllerFile = null;
          let searchFuncName = handlerName;

          if (handlerName.includes('.')) {
            // e.g. userController.createUser
            const parts = handlerName.split('.');
            const objectName = parts[0];
            searchFuncName = parts[1];
            controllerFile = requireMap[objectName] || null;
          } else {
            // Direct function call: createUser
            controllerFile = requireMap[handlerName] || null;
          }

          if (controllerFile) {
            // Trace the function inside the controller file
            const functionLoc = this.findFunctionInFile(controllerFile, searchFuncName);
            this.routes.push({
              path: routePath,
              method,
              routerFile: filePath,
              controllerFile,
              handlerFunction: searchFuncName,
              lineStart: functionLoc ? functionLoc.start : lineStart,
              lineEnd: functionLoc ? functionLoc.end : lineStart + 20
            });
          } else {
            // Fallback: Controller file not resolved, assume defined in same file or unresolved
            this.routes.push({
              path: routePath,
              method,
              routerFile: filePath,
              controllerFile: filePath,
              handlerFunction: handlerName,
              lineStart,
              lineEnd: lineStart + 10
            });
          }
        }
      }
    } catch (err) {
      this.log.push(`[RouteMapper] Error scanning file ${filePath}: ${err.message}`);
    }
  }

  // Searches for a function definition inside a file and returns its line range
  findFunctionInFile(filePath, functionName) {
    try {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      const patterns = [
        new RegExp(`function\\s+${functionName}\\s*\\(`, 'i'),
        new RegExp(`(?:const|let|var)\\s+${functionName}\\s*=\\s*(?:async\\s*)?\\(`, 'i'),
        new RegExp(`(?:exports\\.)?${functionName}\\s*=\\s*(?:async\\s*)?(?:function|\\()`, 'i'),
        new RegExp(`${functionName}\\s*:\\s*(?:async\\s*)?(?:function|\\()`, 'i')
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (patterns.some(p => p.test(line))) {
          const start = i + 1;
          
          // Estimate end line by finding the next function declaration/export or taking a 30 line block
          let end = start + 30;
          for (let j = i + 1; j < Math.min(lines.length, i + 50); j++) {
            const nextLine = lines[j];
            // If we find another export, function statement, or route definition, cap here
            if (
              nextLine.includes('exports.') || 
              nextLine.includes('module.exports') || 
              /function\s+\w+\s*\(/.test(nextLine) ||
              /(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\(/.test(nextLine)
            ) {
              end = j;
              break;
            }
          }
          return { start, end };
        }
      }
    } catch (e) {}
    return null;
  }

  // Maps all routes in the target directory
  mapRoutes(targetDir) {
    this.log.push(`[RouteMapper] Mapping routes statically in directory: ${targetDir}`);
    const files = this.getFileList(targetDir);
    files.forEach(file => {
      this.scanFile(file);
    });
    this.log.push(`[RouteMapper] Static route mapping complete. Extracted ${this.routes.length} paths.`);
    return this.routes;
  }
}

module.exports = { RouteMapper };
