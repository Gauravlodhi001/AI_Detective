/* ==========================================================================
   AI-Detective Corporate Redesign - Charts Rendering Service
   ========================================================================== */

import { store } from './state.js';

export function renderSeverityChart(sev) {
  const canvas = document.getElementById('chart-severity');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  
  if (store.state.severityChartInstance) {
    store.state.severityChartInstance.destroy();
  }

  const severityChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Critical', 'High', 'Medium'],
      datasets: [{
        label: 'Issues Count',
        data: [sev.Critical || 0, sev.High || 0, sev.Medium || 0],
        backgroundColor: ['#e11d48', '#ea580c', '#d97706'],
        borderWidth: 0,
        borderRadius: 4
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { color: 'rgba(255, 255, 255, 0.04)' },
          ticks: { color: '#94a3b8', stepSize: 1 }
        },
        y: {
          grid: { display: false },
          ticks: { color: '#94a3b8' }
        }
      }
    }
  });

  store.set('severityChartInstance', severityChart);
}

export function renderOwaspChart(owaspCounts) {
  const canvas = document.getElementById('chart-owasp');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  
  if (store.state.owaspChartInstance) {
    store.state.owaspChartInstance.destroy();
  }

  const labels = Object.keys(owaspCounts || {}).map(cat => cat.split(':')[0]);
  const data = Object.values(owaspCounts || {});

  if (labels.length === 0) {
    labels.push('Clean');
    data.push(1);
  }

  const bgColors = [
    '#0d9488', '#4f46e5', '#8b5cf6', '#ec4899', 
    '#2563eb', '#10b981', '#f59e0b', '#ea580c', '#e11d48'
  ];

  const owaspChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: labels[0] === 'Clean' ? ['rgba(13, 148, 136, 0.12)'] : bgColors.slice(0, data.length),
        borderColor: labels[0] === 'Clean' ? ['#0d9488'] : ['#0f172a'],
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: { color: '#94a3b8', font: { size: 10.5 } }
        }
      }
    }
  });

  store.set('owaspChartInstance', owaspChart);
}

/**
 * Renders the vertical bar chart inside the privilege audit matrix card.
 */
export function renderPrivilegeAuditMatrix(cweCounts) {
  const canvas = document.getElementById('cockpit-privilege-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  if (store.state.privilegeChartInstance) {
    store.state.privilegeChartInstance.destroy();
  }

  const keys = Object.keys(cweCounts || {});
  let labels = [];
  let data = [];
  let isClean = false;

  if (keys.length === 0) {
    isClean = true;
    // Show 5 primary CWE checks verified as clean/secured
    labels = ['CWE-79', 'CWE-89', 'CWE-798', 'CWE-95', 'CWE-22'];
    data = [1, 1, 1, 1, 1];
  } else {
    labels = keys;
    data = Object.values(cweCounts || {});
  }

  const privilegeChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: isClean ? 'Checks Passed' : 'CWE Occurrences',
        data,
        backgroundColor: isClean ? 'rgba(16, 185, 129, 0.45)' : '#ffd79b', // Green for clean tests, amber for vulns
        borderColor: isClean ? '#10b981' : '#e7c186',
        borderWidth: 1,
        borderRadius: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: '#9a8f81', font: { family: 'JetBrains Mono, monospace', size: 9 } }
        },
        y: {
          grid: { color: 'rgba(255, 255, 255, 0.04)' },
          min: 0,
          ticks: { 
            color: '#9a8f81', 
            font: { family: 'JetBrains Mono, monospace', size: 9 }, 
            stepSize: 1,
            precision: 0,
            callback: function(value) {
              if (Number.isInteger(value)) return value;
              return null;
            }
          }
        }
      }
    }
  });

  store.set('privilegeChartInstance', privilegeChart);
}

/**
 * Renders the line graph inside the critical findings trend card.
 */
export function renderFindingsHistoryTrend(reports) {
  const canvas = document.getElementById('cockpit-trend-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  if (store.state.trendChartInstance) {
    store.state.trendChartInstance.destroy();
  }

  // Sort chronologically (oldest to newest)
  const sortedReports = [...reports].sort((a, b) => new Date(a.scanTime) - new Date(b.scanTime));
  // Take last 7 scans
  const recentReports = sortedReports.slice(-7);

  const labels = recentReports.map((r) => {
    const d = new Date(r.scanTime);
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
  });

  const data = recentReports.map(r => r.findings?.length || 0);

  if (labels.length === 0) {
    labels.push('No Scans');
    data.push(0);
  }

  const trendChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'Total Findings',
        data,
        borderColor: '#b0c6ff', // Glowing secondary blue
        backgroundColor: 'rgba(176, 198, 255, 0.05)',
        borderWidth: 2,
        tension: 0.35,
        fill: true,
        pointBackgroundColor: '#b0c6ff',
        pointRadius: 3
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          grid: { display: false },
          ticks: { color: '#9a8f81', font: { family: 'JetBrains Mono, monospace', size: 9 } }
        },
        y: {
          grid: { color: 'rgba(255, 255, 255, 0.04)' },
          min: 0,
          ticks: { 
            color: '#9a8f81', 
            font: { family: 'JetBrains Mono, monospace', size: 9 },
            stepSize: 1,
            precision: 0,
            callback: function(value) {
              if (Number.isInteger(value)) return value;
              return null;
            }
          }
        }
      }
    }
  });

  store.set('trendChartInstance', trendChart);
}
