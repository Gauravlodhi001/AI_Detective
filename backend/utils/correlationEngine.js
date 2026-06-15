const fs = require('fs');
const path = require('path');
const { TaintEngine } = require('./taintEngine');

class CorrelationEngine {
  constructor(log) {
    this.log = log || [];
    this.importGraph = {}; // Maps: absoluteFilePath -> Array of files importing it
    this.taintEngine = new TaintEngine(this.log);
  }

  // Recursively walks target directory to find JS files
  getFileList(dir, fileList = []) {
    if (!fs.existsSync(dir)) return fileList;
    const files = fs.readdirSync(dir);
    for (const file of files) {
      const filePath = path.join(dir, file);
      if (file === 'node_modules' || file === '.git' || file === 'cloned_repos' || file === 'uploads' || file === 'reports' || file === 'scratch') {
        continue;
      }
      const stat = fs.statSync(filePath);
      if (stat.isDirectory()) {
        this.getFileList(filePath, fileList);
      } else if (filePath.endsWith('.js') || filePath.endsWith('.json')) {
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

  // Builds the import dependency graph of the codebase
  buildImportGraph(targetDir) {
    this.log.push(`[CorrelationEngine] Building codebase import dependency graph...`);
    const files = this.getFileList(targetDir);
    this.importGraph = {};

    files.forEach(filePath => {
      try {
        if (!filePath.endsWith('.js')) return;
        const content = fs.readFileSync(filePath, 'utf-8');
        
        // Match require()
        const requireRegex = /require\s*\(\s*['"`]([^'"`]+)['"`]\s*\)/g;
        let match;
        while ((match = requireRegex.exec(content)) !== null) {
          const reqPath = match[1];
          // Skip core node modules or npm packages
          if (reqPath.startsWith('.') || reqPath.startsWith('/') || path.isAbsolute(reqPath)) {
            const resolved = this.resolveRequirePath(filePath, reqPath);
            if (resolved) {
              this.importGraph[resolved] = this.importGraph[resolved] || [];
              if (!this.importGraph[resolved].includes(filePath)) {
                this.importGraph[resolved].push(filePath);
              }
            }
          }
        }
      } catch (err) {
        // Ignore
      }
    });
    this.log.push(`[CorrelationEngine] Import dependency graph built.`);
  }

  // Trace which endpoints are exposed by a file using BFS up the import graph
  traceExposedEndpoints(absoluteFilePath, routesMap) {
    const exposed = [];
    const queue = [absoluteFilePath];
    const visited = new Set();

    while (queue.length > 0) {
      const current = queue.shift();
      if (visited.has(current)) continue;
      visited.add(current);

      // Check if current file has direct routes registered in the routesMap
      const matchedRoutes = routesMap.filter(r => r.controllerFile === current || r.routerFile === current);
      matchedRoutes.forEach(r => {
        const routeKey = `${r.method} ${r.path}`;
        if (!exposed.some(e => e.routeKey === routeKey)) {
          exposed.push({
            routeKey,
            path: r.path,
            method: r.method,
            handler: r.handlerFunction,
            lineStart: r.lineStart,
            lineEnd: r.lineEnd
          });
        }
      });

      // Add parent files that require/import the current file to the queue
      const importers = this.importGraph[current] || [];
      importers.forEach(imp => {
        if (!visited.has(imp)) {
          queue.push(imp);
        }
      });
    }

    return exposed;
  }

  // Correlates static SAST findings, secrets, and dependencies to dynamic runtime endpoints
  correlate(sastFindings, dastFindings, routesMap, targetDir) {
    this.log.push('[CorrelationEngine] Starting White Box vulnerability correlation...');
    this.buildImportGraph(targetDir);

    const correlatedFindings = [];
    const unmatchedSast = [];

    // Map to quickly find routes by file and line scope
    const findRouteByLine = (filePath, lineNum) => {
      const absolutePath = path.resolve(filePath);
      return routesMap.find(r => 
        (r.controllerFile === absolutePath || r.routerFile === absolutePath) &&
        (lineNum >= r.lineStart && lineNum <= r.lineEnd)
      );
    };

    // 1. Process SAST findings and attempt to correlate with endpoints
    sastFindings.forEach(sast => {
      const absoluteFilePath = path.resolve(targetDir, sast.path || '');
      const lineNum = sast.line || 0;
      
      // Try to find a route mapping the exact controller handler function scope
      const directRoute = findRouteByLine(absoluteFilePath, lineNum);
      
      // Run TaintEngine to trace data flows in this controller file
      const taintFlows = this.taintEngine.analyzeFile(absoluteFilePath);
      const matchedTaint = taintFlows.find(t => t.line === lineNum);

      if (directRoute) {
        this.log.push(`[CorrelationEngine] Correlated SAST finding "${sast.title}" to endpoint: ${directRoute.method} ${directRoute.path} (Direct)`);
        correlatedFindings.push({
          ...sast,
          isCorrelated: true,
          whiteBoxType: 'sast_to_dast',
          endpoint: `${directRoute.method} ${directRoute.path}`,
          endpointPath: directRoute.path,
          endpointMethod: directRoute.method,
          handler: directRoute.handlerFunction,
          taintFlow: matchedTaint || null,
          codeLocation: {
            file: sast.path,
            line: lineNum,
            lineStart: directRoute.lineStart,
            lineEnd: directRoute.lineEnd,
            codeSnippet: sast.code || ''
          }
        });
      } else {
        // Fallback: Trace general exposure via imports
        const exposed = this.traceExposedEndpoints(absoluteFilePath, routesMap);
        if (exposed.length > 0) {
          this.log.push(`[CorrelationEngine] Correlated SAST finding "${sast.title}" in helper file ${sast.path} to exposed paths: ${exposed.map(e => e.routeKey).join(', ')}`);
          exposed.forEach(exp => {
            // Check if there is a taint flow mapped inside the helper file
            const helperTaintFlows = this.taintEngine.analyzeFile(absoluteFilePath);
            const helperMatchedTaint = helperTaintFlows.find(t => t.line === lineNum);

            correlatedFindings.push({
              ...sast,
              id: `${sast.id}-${exp.method}-${exp.path.replace(/\//g, '_')}`, // Unique correlated id
              isCorrelated: true,
              whiteBoxType: 'sast_helper_to_dast',
              endpoint: exp.routeKey,
              endpointPath: exp.path,
              endpointMethod: exp.method,
              handler: exp.handler,
              taintFlow: helperMatchedTaint || null,
              codeLocation: {
                file: sast.path,
                line: lineNum,
                lineStart: exp.lineStart,
                lineEnd: exp.lineEnd,
                codeSnippet: sast.code || ''
              }
            });
          });
        } else {
          unmatchedSast.push(sast);
        }
      }
    });

    // 2. Correlate dynamic WAPT/DAST findings with static code scopes
    const correlatedDast = [];
    dastFindings.forEach(dast => {
      // Find if we have code references for the scanned path
      const matchingRoute = routesMap.find(r => r.path === dast.endpointPath && r.method === dast.endpointMethod);
      if (matchingRoute) {
        correlatedDast.push({
          ...dast,
          isCorrelated: true,
          whiteBoxType: 'dast_to_code',
          codeLocation: {
            file: path.relative(targetDir, matchingRoute.controllerFile),
            line: matchingRoute.lineStart,
            lineStart: matchingRoute.lineStart,
            lineEnd: matchingRoute.lineEnd,
            handler: matchingRoute.handlerFunction
          }
        });
      } else {
        correlatedDast.push(dast);
      }
    });

    this.log.push(`[CorrelationEngine] Correlation complete. Found ${correlatedFindings.length} White Box code-to-endpoint mappings.`);
    return {
      correlatedFindings, // Merged SAST-to-endpoint findings
      correlatedDast,      // DAST findings decorated with code paths
      unmatchedSast        // Pure SAST findings without endpoint exposures
    };
  }
}

module.exports = { CorrelationEngine };
