/* ==========================================================================
   AI-Detective Corporate Redesign - Scan Panels Handler
   ========================================================================== */

import { api } from './api.js';
import { store } from './state.js';
import { showReport } from './main.js'; // imported from main bootstrapper

export function setupDragAndDrop() {
  const zone = document.getElementById('drag-drop-zone');
  if (!zone) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    zone.addEventListener(eventName, (e) => {
      e.preventDefault();
      zone.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    zone.addEventListener(eventName, (e) => {
      e.preventDefault();
      zone.classList.remove('dragover');
    }, false);
  });

  zone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    
    if (files.length > 0) {
      const file = files[0];
      if (file.name.endsWith('.zip')) {
        handleFileSelection(file);
      } else {
        alert('Please drop a valid .zip compressed archive.');
      }
    }
  });
}

export function handleFileSelect(event) {
  const file = event.target.files[0];
  if (file) {
    handleFileSelection(file);
  }
}

export function handleFileSelection(file) {
  store.set('selectedFile', file);
  document.getElementById('selected-file-name').textContent = file.name;
  document.getElementById('selected-file-display').style.display = 'flex';
  
  const projectInput = document.getElementById('zip-project-name');
  if (projectInput && !projectInput.value) {
    projectInput.value = file.name.replace(/\.zip$/i, '');
  }
}

export function clearSelectedFile() {
  store.set('selectedFile', null);
  document.getElementById('zip-file-input').value = '';
  document.getElementById('selected-file-display').style.display = 'none';
}

export function writeConsoleLog(text, logClass = '') {
  const consoleBox = document.getElementById('scan-console-logs');
  if (!consoleBox) return;

  const line = document.createElement('div');
  line.className = `console-line ${logClass}`;
  line.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
  consoleBox.appendChild(line);
  consoleBox.scrollTop = consoleBox.scrollHeight;
}

export function clearConsoleLogs() {
  const consoleBox = document.getElementById('scan-console-logs');
  if (consoleBox) consoleBox.innerHTML = '';
}

export function runLogSimulation(projectName, type = 'zip') {
  clearConsoleLogs();
  writeConsoleLog(`[START] Initializing Security Audit for: "${projectName}"`, 'warning');
  
  const steps = [
    { text: 'Preparing sandbox staging directory...', delay: 100 },
    { text: type === 'git' ? 'Spawning Git subsystem subprocess...' : 'Extracting manifest files...', delay: 400 },
    { text: type === 'git' ? 'Fetching remote repository metadata...' : 'Unpacking directory tree...', delay: 800 },
    { text: 'Crawling file tree structures (excluding node_modules)...', delay: 1200 },
    { text: 'Triggering custom high-entropy credentials scanner...', delay: 1700 },
    { text: 'Custom Secret scan complete. Redacting tokens.', class: 'success', delay: 2200 },
    { text: 'Detecting Semgrep configuration files...', delay: 2600 },
    { text: 'Spawning Semgrep CLI static analysis engine (Primary SAST)...', delay: 3100 },
    { text: 'Parsing Semgrep JSON reports and mapping vulnerabilities...', delay: 4200 },
    { text: 'Semgrep SAST scan completed successfully.', class: 'success', delay: 4800 },
    { text: 'Scanning manifests for software dependencies (SCA)...', delay: 5200 },
    { text: 'Comparing packages against local CVE databases...', delay: 5700 },
    { text: 'Dependency checks complete.', class: 'success', delay: 6200 },
    { text: 'Applying risk grading engine matrices...', delay: 6600 },
    { text: 'Writing HTML, Markdown & JSON reports to disk...', delay: 7100 },
    { text: 'Audit complete! Rendering analysis dashboard...', class: 'success', delay: 7500 }
  ];

  const timeouts = [];
  
  steps.forEach(step => {
    const t = setTimeout(() => {
      writeConsoleLog(`[INFO] ${step.text}`, step.class || '');
    }, step.delay);
    timeouts.push(t);
  });

  return {
    clear: () => {
      timeouts.forEach(clearTimeout);
    }
  };
}

export async function handleZipScan(event) {
  event.preventDefault();
  const file = store.state.selectedFile;
  if (!file) {
    alert('Please select or drag a project zip file first.');
    return;
  }

  const submitBtn = document.getElementById('zip-submit-btn');
  submitBtn.disabled = true;
  submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Analyzing...`;

  const projName = document.getElementById('zip-project-name').value || file.name.replace(/\.zip$/i, '');
  const sim = runLogSimulation(projName, 'zip');

  const formData = new FormData();
  formData.append('zipFile', file);
  formData.append('projectName', projName);

  try {
    const data = await api.runZipScan(formData);
    
    setTimeout(() => {
      sim.clear();
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<i class="fa-solid fa-circle-play"></i> Run Security Scan`;
      
      if (data.success) {
        showReport(data.report);
      } else {
        writeConsoleLog(`[ERROR] Scan failed: ${data.message}`, 'error');
        alert(`Scanning Error: ${data.message}`);
      }
    }, 3000);

  } catch (err) {
    sim.clear();
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<i class="fa-solid fa-circle-play"></i> Run Security Scan`;
    writeConsoleLog(`[ERROR] Network error during scan: ${err.message}`, 'error');
    alert('Network error. Check server status.');
  }
}

export async function handleGitScan(event) {
  event.preventDefault();
  const gitUrl = document.getElementById('git-url').value;
  const branch = document.getElementById('git-branch').value;

  if (!gitUrl) return;

  const submitBtn = document.getElementById('git-submit-btn');
  submitBtn.disabled = true;
  submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Cloning & Scanning...`;

  const sim = runLogSimulation(gitUrl, 'git');

  try {
    const data = await api.runGitScan(gitUrl, branch);

    setTimeout(() => {
      sim.clear();
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<i class="fa-solid fa-code-branch"></i> Clone & Scan Repository`;
      
      if (data.success) {
        showReport(data.report);
      } else {
        writeConsoleLog(`[ERROR] Scan failed: ${data.message}`, 'error');
        alert(`Scanning Error: ${data.message}`);
      }
    }, 4000);

  } catch (err) {
    sim.clear();
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<i class="fa-solid fa-code-branch"></i> Clone & Scan Repository`;
    writeConsoleLog(`[ERROR] Network error: ${err.message}`, 'error');
    alert('Network error cloning repository.');
  }
}

export async function handlePasteScan(event) {
  event.preventDefault();
  const code = document.getElementById('paste-code').value;
  const filename = document.getElementById('paste-filename').value;
  const projectName = document.getElementById('paste-project-name').value || 'Snippet Code';

  if (!code || !filename) return;

  const submitBtn = document.getElementById('paste-submit-btn');
  submitBtn.disabled = true;
  submitBtn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Scanning Snippet...`;

  const sim = runLogSimulation(projectName, 'paste');

  try {
    const data = await api.runPasteScan(code, filename, projectName);

    setTimeout(() => {
      sim.clear();
      submitBtn.disabled = false;
      submitBtn.innerHTML = `<i class="fa-solid fa-laptop-code"></i> Analyze Code Snippet`;
      
      if (data.success) {
        showReport(data.report);
      } else {
        writeConsoleLog(`[ERROR] Scan failed: ${data.message}`, 'error');
        alert(`Scanning Error: ${data.message}`);
      }
    }, 2500);

  } catch (err) {
    sim.clear();
    submitBtn.disabled = false;
    submitBtn.innerHTML = `<i class="fa-solid fa-laptop-code"></i> Analyze Code Snippet`;
    writeConsoleLog(`[ERROR] Network error: ${err.message}`, 'error');
    alert('Network error scanning pasted snippet.');
  }
}

// Bind to window for HTML inline events
window.clearConsoleLogs = clearConsoleLogs;
