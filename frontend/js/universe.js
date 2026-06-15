/* ==========================================================================
   AI-Detective Corporate Redesign - Three.js 3D Correlation Universe
   ========================================================================== */

let scene, camera, renderer, container;
let nodesGroup, connectionsGroup, epicenterGroup;
let particles;
let hoveredNode = null;
let animationFrameId = null;

// Track all active nodes to map connections and lookups
let nodeMap = {
  sast: {},
  sca: {},
  wapt: {}
};

/**
 * Initializes the Three.js 3D Viewport.
 */
export function initUniverse(containerId) {
  container = document.getElementById(containerId);
  if (!container) {
    console.error(`Three.js container #${containerId} not found.`);
    return;
  }

  // If already initialized, clean up old DOM element and recreate
  if (renderer) {
    if (renderer.domElement && container.contains(renderer.domElement)) {
      container.removeChild(renderer.domElement);
    }
    cancelAnimationFrame(animationFrameId);
  }

  const width = container.clientWidth || 600;
  const height = container.clientHeight || 400;

  // Scene setup
  scene = new THREE.Scene();

  // Perspective Camera
  camera = new THREE.PerspectiveCamera(60, width / height, 0.1, 1000);
  camera.position.set(0, 0, 8);

  // WebGL Renderer with transparency for background canvas blend
  renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
  renderer.setSize(width, height);
  renderer.setPixelRatio(window.devicePixelRatio);
  container.appendChild(renderer.domElement);

  // Create groups for organization
  epicenterGroup = new THREE.Group();
  nodesGroup = new THREE.Group();
  connectionsGroup = new THREE.Group();

  scene.add(epicenterGroup);
  scene.add(nodesGroup);
  scene.add(connectionsGroup);

  // Digital Dust Particle System
  const particleGeo = new THREE.BufferGeometry();
  const particleCount = 250;
  const posArray = new Float32Array(particleCount * 3);
  for (let i = 0; i < particleCount * 3; i++) {
    posArray[i] = (Math.random() - 0.5) * 12;
  }
  particleGeo.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
  const particleMat = new THREE.PointsMaterial({
    size: 0.035,
    color: 0x06b6d4,
    transparent: true,
    opacity: 0.35
  });
  particles = new THREE.Points(particleGeo, particleMat);
  scene.add(particles);

  // Build the Central Posture Node (Epicenter)
  // Rotating dashed/solid rings
  const ringGeo1 = new THREE.TorusGeometry(1.2, 0.015, 16, 100);
  const ringMat1 = new THREE.MeshBasicMaterial({ color: 0x06b6d4, transparent: true, opacity: 0.35 });
  const ring1 = new THREE.Mesh(ringGeo1, ringMat1);
  epicenterGroup.add(ring1);

  const ringGeo2 = new THREE.TorusGeometry(0.8, 0.01, 16, 100);
  const ringMat2 = new THREE.MeshBasicMaterial({ color: 0x06b6d4, transparent: true, opacity: 0.2 });
  const ring2 = new THREE.Mesh(ringGeo2, ringMat2);
  ring2.rotation.x = Math.PI / 3;
  epicenterGroup.add(ring2);

  // Core glowing posture sphere
  const coreGeo = new THREE.SphereGeometry(0.35, 32, 32);
  const coreMat = new THREE.MeshPhongMaterial({
    color: 0x06b6d4,
    emissive: 0x06b6d4,
    emissiveIntensity: 0.6,
    transparent: true,
    opacity: 0.85
  });
  const core = new THREE.Mesh(coreGeo, coreMat);
  epicenterGroup.add(core);

  // Add Lights
  const ambientLight = new THREE.AmbientLight(0xffffff, 0.55);
  scene.add(ambientLight);

  const dirLight1 = new THREE.DirectionalLight(0xffffff, 0.8);
  dirLight1.position.set(5, 10, 7);
  scene.add(dirLight1);

  const dirLight2 = new THREE.DirectionalLight(0x06b6d4, 0.5);
  dirLight2.position.set(-5, -5, -2);
  scene.add(dirLight2);

  // Raycasting & Interaction Listeners
  setupRaycaster();

  // Resize Listener
  window.addEventListener('resize', handleResize);

  // Start rendering
  animate();
}

/**
 * Handle canvas resizing.
 */
function handleResize() {
  if (!container || !camera || !renderer) return;
  const width = container.clientWidth;
  const height = container.clientHeight;
  camera.aspect = width / height;
  camera.updateProjectionMatrix();
  renderer.setSize(width, height);
}

/**
 * Setup Raycaster for hover/click interactions.
 */
function setupRaycaster() {
  const raycaster = new THREE.Raycaster();
  const mouse = new THREE.Vector2();
  const tooltip = document.getElementById('floating-node-meta');
  const tooltipDesc = tooltip ? tooltip.querySelector('.node-meta-desc') : null;
  const tooltipTitle = tooltip ? tooltip.querySelector('.node-meta-title') : null;

  function onMouseMove(event) {
    const rect = renderer.domElement.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(nodesGroup.children);

    if (intersects.length > 0) {
      const intersected = intersects[0].object;
      
      if (hoveredNode !== intersected) {
        if (hoveredNode) {
          // Reset old hovered node
          hoveredNode.scale.set(1, 1, 1);
          hoveredNode.material.emissiveIntensity = hoveredNode.userData.originalEmissiveIntensity || 0.6;
        }

        hoveredNode = intersected;
        // Highlight active node
        hoveredNode.scale.set(1.3, 1.3, 1.3);
        hoveredNode.material.emissiveIntensity = 1.2;
      }

      // Show and update tooltip
      if (tooltip && tooltipDesc) {
        tooltip.style.display = 'block';
        const data = hoveredNode.userData;

        if (data.type === 'sast_file') {
          if (tooltipTitle) tooltipTitle.textContent = 'SAST File Node';
          tooltipDesc.innerHTML = `
            <strong>File:</strong> ${data.path}<br/>
            <strong>Findings:</strong> ${data.findings.length} code vulns
          `;
          tooltip.style.borderLeftColor = 'var(--color-low)'; // blue
        } else if (data.type === 'sca') {
          if (tooltipTitle) tooltipTitle.textContent = 'SCA Package Node';
          tooltipDesc.innerHTML = `
            <strong>Package:</strong> ${data.name}<br/>
            <strong>Severity:</strong> ${data.findings[0]?.severity || 'High'}<br/>
            <strong>CWE:</strong> ${data.findings[0]?.cwe || 'CWE-1395'}
          `;
          tooltip.style.borderLeftColor = 'var(--color-accent)'; // yellow
        } else if (data.type === 'wapt') {
          if (tooltipTitle) tooltipTitle.textContent = 'WAPT Endpoint Node';
          tooltipDesc.innerHTML = `
            <strong>Route:</strong> ${data.endpoint}<br/>
            <strong>Status:</strong> Exposed Endpoint<br/>
            <strong>Correlations:</strong> ${data.findings.length} findings
          `;
          tooltip.style.borderLeftColor = 'var(--color-critical)'; // orange/red
        }
      }
    } else {
      if (hoveredNode) {
        // Reset scale and emissive intensity
        hoveredNode.scale.set(1, 1, 1);
        hoveredNode.material.emissiveIntensity = hoveredNode.userData.originalEmissiveIntensity || 0.6;
        hoveredNode = null;
      }
      if (tooltip) {
        tooltip.style.display = 'none';
      }
    }
  }

  function onClick() {
    if (hoveredNode) {
      const data = hoveredNode.userData;
      // Dispatch custom selection event to document
      const event = new CustomEvent('nodeSelected', {
        detail: {
          type: data.type,
          path: data.path,
          name: data.name,
          endpoint: data.endpoint,
          findings: data.findings
        }
      });
      window.dispatchEvent(event);
      
      // Flash the selected node visually
      const origColor = hoveredNode.material.color.getHex();
      hoveredNode.material.color.setHex(0xffffff);
      setTimeout(() => {
        if (hoveredNode && hoveredNode.userData.color) {
          hoveredNode.material.color.setHex(hoveredNode.userData.color);
        } else {
          // Re-lookup or fallback
          const targetNode = nodesGroup.children.find(n => n === hoveredNode);
          if (targetNode) targetNode.material.color.setHex(targetNode.userData.color);
        }
      }, 150);
    }
  }

  // Bind mouse handlers
  renderer.domElement.addEventListener('mousemove', onMouseMove);
  renderer.domElement.addEventListener('click', onClick);
}

/**
 * Builds the 3D Node Graph representing SAST, SCA and WAPT routes.
 */
export function buildGraph(report) {
  if (!scene) {
    console.warn('Three.js scene not initialized yet.');
    return;
  }

  // Clear previous nodes and connections
  while (nodesGroup.children.length > 0) {
    const obj = nodesGroup.children[0];
    nodesGroup.remove(obj);
  }
  while (connectionsGroup.children.length > 0) {
    const obj = connectionsGroup.children[0];
    connectionsGroup.remove(obj);
  }

  nodeMap = { sast: {}, sca: {}, wapt: {} };

  const findings = report ? report.findings || [] : [];
  
  // 1. Group Findings by Category
  const sastFindings = [];
  const scaFindings = [];
  const waptEndpoints = new Set();
  const waptExposed = new Set(); // all mapped routes (including clean ones)
  const correlatedMap = {};
  const fileToRoutes = {}; // track which files implementing which routes

  findings.forEach(f => {
    if (f.rule_id && f.rule_id.startsWith('outdated-package-')) {
      scaFindings.push(f);
    } else {
      sastFindings.push(f);
    }

    if (f.isCorrelated && f.endpoint) {
      waptEndpoints.add(f.endpoint);
      waptExposed.add(f.endpoint);
      if (!correlatedMap[f.endpoint]) {
        correlatedMap[f.endpoint] = [];
      }
      correlatedMap[f.endpoint].push(f);
    }
  });

  // Also collect any route information if it exists in report.routes
  if (report && report.routes && Array.isArray(report.routes)) {
    report.routes.forEach(r => {
      const routeKey = `${r.method} ${r.path}`;
      waptExposed.add(routeKey);
      if (r.controllerFile) {
        const parts = r.controllerFile.split(/[\\/]/);
        const baseName = parts.pop();
        if (baseName) {
          if (!fileToRoutes[baseName]) fileToRoutes[baseName] = [];
          fileToRoutes[baseName].push(routeKey);
        }
      }
    });
  }

  // If there are no findings and no exposed routes, generate clean baseline network
  if (findings.length === 0 && waptExposed.size === 0) {
    const baselineComponents = [
      { type: 'sast_file', name: 'app.js', path: 'app.js' },
      { type: 'sast_file', name: 'routes/auth.js', path: 'routes/auth.js' },
      { type: 'sast_file', name: 'controllers/auth.js', path: 'controllers/auth.js' },
      { type: 'sast_file', name: 'config/db.js', path: 'config/db.js' },
      { type: 'sca', name: 'express', pkgName: 'express' },
      { type: 'sca', name: 'jsonwebtoken', pkgName: 'jsonwebtoken' },
      { type: 'wapt', name: 'POST /api/login', endpoint: 'POST /api/login' },
      { type: 'wapt', name: 'GET /api/user/profile', endpoint: 'GET /api/user/profile' }
    ];

    baselineComponents.forEach((comp, idx) => {
      const angle = (idx / baselineComponents.length) * Math.PI * 2;
      let radius = 3.2;
      let nodeColor = 0x10b981; // Secure Green

      if (comp.type === 'sast_file') {
        radius = 2.6;
        nodeColor = 0x06b6d4; // Cyan for secure code files
      } else if (comp.type === 'sca') {
        radius = 4.0;
        nodeColor = 0x10b981; // Green for secure dependencies
      } else if (comp.type === 'wapt') {
        radius = 5.4;
        nodeColor = 0x10b981; // Green for secure routes
      }

      const pos = new THREE.Vector3(
        Math.cos(angle) * radius,
        Math.sin(angle) * radius,
        (Math.random() - 0.5) * 0.8
      );

      const mesh = createNodeMesh(comp.type, nodeColor, pos, 0.13);
      mesh.userData = {
        type: comp.type,
        path: comp.path || '',
        name: comp.pkgName || comp.name,
        endpoint: comp.endpoint || '',
        findings: [], // Clean, no findings!
        color: nodeColor,
        isBaseline: true
      };
      nodesGroup.add(mesh);

      // Draw faint link to center
      drawLink(new THREE.Vector3(0, 0, 0), pos, nodeColor, 0.15);
    });

    // Draw some mock connections representing secure data flows
    const sastNodes = nodesGroup.children.filter(n => n.userData.type === 'sast_file');
    const waptNodes = nodesGroup.children.filter(n => n.userData.type === 'wapt');
    if (sastNodes.length >= 3 && waptNodes.length >= 2) {
      drawBezierCurve(sastNodes[1].position, waptNodes[0].position, 0x10b981, 0.45);
      drawBezierCurve(sastNodes[2].position, waptNodes[1].position, 0x10b981, 0.45);
    }

    // Update central gauge signal score
    const scoreArc = document.getElementById('dashboard-score-arc');
    if (scoreArc) scoreArc.style.strokeDashoffset = 0; // Grade A 100/100
    return;
  }

  // 2. Generate SAST File Nodes
  // We'll collect all vulnerable files, plus any mapped controller files from the routes
  const sastFiles = {};
  sastFindings.forEach(f => {
    if (!sastFiles[f.path]) sastFiles[f.path] = [];
    sastFiles[f.path].push(f);
  });

  // Also extract clean files from report.routes
  const cleanFiles = new Set();
  if (report && report.routes && Array.isArray(report.routes)) {
    report.routes.forEach(r => {
      if (r.controllerFile) {
        let rel = r.controllerFile;
        if (rel.includes('uploads')) {
          const splitParts = rel.split(/[\\/]uploads[\\/]/);
          if (splitParts[1]) {
            rel = splitParts[1].split(/[\\/]/).slice(1).join('/');
          }
        } else {
          // Fallback simple base
          rel = rel.split(/[\\/]/).pop();
        }
        if (rel && !sastFiles[rel]) {
          cleanFiles.add(rel);
        }
      }
    });
  }

  const allFileKeys = [...Object.keys(sastFiles), ...Array.from(cleanFiles)];
  const totalFiles = allFileKeys.length;

  allFileKeys.forEach((pathKey, idx) => {
    const angle = (idx / Math.max(1, totalFiles)) * Math.PI * 2;
    const radius = 2.8;
    const pos = new THREE.Vector3(
      Math.cos(angle) * radius,
      Math.sin(angle) * radius,
      (Math.random() - 0.5) * 1.2
    );

    const hasVulns = sastFiles[pathKey] && sastFiles[pathKey].length > 0;
    const nodeColor = hasVulns ? 0x2979ff : 0x06b6d4; // Blue for vulnerable code file, Cyan for clean
    const mesh = createNodeMesh('sast_file', nodeColor, pos, 0.16);
    mesh.userData = {
      type: 'sast_file',
      path: pathKey,
      findings: sastFiles[pathKey] || [],
      color: nodeColor
    };
    nodesGroup.add(mesh);
    nodeMap.sast[pathKey] = mesh;

    // Draw link to central posture core
    drawLink(new THREE.Vector3(0, 0, 0), pos, nodeColor, 0.15);
  });

  // 3. Generate SCA Package Nodes (Yellow)
  const scaPackages = {};
  scaFindings.forEach(f => {
    const pkgName = f.rule_id.replace('outdated-package-', '');
    if (!scaPackages[pkgName]) {
      scaPackages[pkgName] = [];
    }
    scaPackages[pkgName].push(f);
  });

  const scaKeys = Object.keys(scaPackages);
  const totalSca = scaKeys.length;
  scaKeys.forEach((pkgName, idx) => {
    const angle = (idx / Math.max(1, totalSca)) * Math.PI * 2 + 0.6;
    const radius = 4.2;
    const pos = new THREE.Vector3(
      Math.cos(angle) * radius,
      Math.sin(angle) * radius,
      (Math.random() - 0.5) * 1.5
    );

    const nodeColor = 0xffd600; // Yellow for vulnerable dependency
    const mesh = createNodeMesh('sca', nodeColor, pos, 0.14);
    mesh.userData = {
      type: 'sca',
      name: pkgName,
      findings: scaPackages[pkgName],
      color: nodeColor
    };
    nodesGroup.add(mesh);
    nodeMap.sca[pkgName] = mesh;

    // Draw link to center
    drawLink(new THREE.Vector3(0, 0, 0), pos, 0xffd600, 0.12);
  });

  // 4. Generate WAPT Endpoint Nodes (Orange / Green)
  const endpointArray = Array.from(waptExposed);
  const totalWapt = endpointArray.length;
  endpointArray.forEach((endpointKey, idx) => {
    const angle = (idx / Math.max(1, totalWapt)) * Math.PI * 2 + 1.2;
    const radius = 5.5;
    const pos = new THREE.Vector3(
      Math.cos(angle) * radius,
      Math.sin(angle) * radius,
      (Math.random() - 0.5) * 1.0
    );

    const hasVulns = waptEndpoints.has(endpointKey);
    const nodeColor = hasVulns ? 0xea580c : 0x10b981; // Orange for vulnerable routes, Green for clean
    const mesh = createNodeMesh('wapt', nodeColor, pos, 0.18);
    mesh.userData = {
      type: 'wapt',
      endpoint: endpointKey,
      findings: correlatedMap[endpointKey] || [],
      color: nodeColor
    };
    nodesGroup.add(mesh);
    nodeMap.wapt[endpointKey] = mesh;

    // Faint link to center
    drawLink(new THREE.Vector3(0, 0, 0), pos, nodeColor, 0.1);
  });

  // 5. Draw Stitch Correlation Lines
  findings.forEach(f => {
    if (f.isCorrelated && f.endpoint && f.path) {
      const sastNode = nodeMap.sast[f.path];
      const waptNode = nodeMap.wapt[f.endpoint];

      if (sastNode && waptNode) {
        drawBezierCurve(sastNode.position, waptNode.position, 0x06b6d4, 0.7);
      }
    }
  });

  // Also draw connections for clean routes to their respective controllers if mapped!
  if (report && report.routes && Array.isArray(report.routes)) {
    endpointArray.forEach(endpointKey => {
      const waptNode = nodeMap.wapt[endpointKey];
      if (!waptNode || waptNode.userData.findings.length > 0) return; // skip if vulnerable (already handled)

      const routeInfo = report.routes.find(r => `${r.method} ${r.path}` === endpointKey);
      if (routeInfo && routeInfo.controllerFile) {
        let rel = routeInfo.controllerFile;
        if (rel.includes('uploads')) {
          const splitParts = rel.split(/[\\/]uploads[\\/]/);
          if (splitParts[1]) {
            rel = splitParts[1].split(/[\\/]/).slice(1).join('/');
          }
        } else {
          rel = rel.split(/[\\/]/).pop();
        }
        const sastNode = nodeMap.sast[rel];
        if (sastNode) {
          drawBezierCurve(sastNode.position, waptNode.position, 0x10b981, 0.35);
        }
      }
    });
  }

  // Update central gauge signal score based on metrics
  const scoreArc = document.getElementById('dashboard-score-arc');
  const score = report.metrics?.securityScore || 0;
  if (scoreArc) {
    const circumference = 251.2;
    const offset = circumference - (score / 100) * circumference;
    scoreArc.style.strokeDashoffset = offset;
  }
}

/**
 * Creates a standard node mesh sphere.
 */
function createNodeMesh(type, color, pos, size) {
  let geo;
  if (type === 'sast_file') {
    // Thin rectangle box representing a document page/file
    geo = new THREE.BoxGeometry(size * 1.5, size * 2.0, size * 0.12);
  } else if (type === 'sca') {
    // Perfect cube representing a library package block
    geo = new THREE.BoxGeometry(size * 1.3, size * 1.3, size * 1.3);
  } else if (type === 'wapt') {
    // Disc/Cylinder representing a dynamic target endpoint
    geo = new THREE.CylinderGeometry(size * 1.0, size * 1.0, size * 0.4, 16);
  } else {
    // Fallback sphere
    geo = new THREE.SphereGeometry(size, 16, 16);
  }
  
  const mat = new THREE.MeshPhongMaterial({
    color: color,
    emissive: color,
    emissiveIntensity: 0.6,
    shininess: 30,
    transparent: true,
    opacity: 0.9
  });
  const mesh = new THREE.Mesh(geo, mat);
  mesh.position.copy(pos);
  
  // Give files and WAPT nodes a slight random orientation to look organic in 3D space
  if (type === 'sast_file') {
    mesh.rotation.set(
      (Math.random() - 0.5) * 0.3,
      (Math.random() - 0.5) * 0.3,
      (Math.random() - 0.5) * 0.2
    );
  } else if (type === 'wapt') {
    mesh.rotation.x = Math.PI / 2; // Flat disc orientation facing screen
  }
  
  mesh.userData.originalEmissiveIntensity = 0.6;
  return mesh;
}

/**
 * Draws a faint straight lines mapping constellation paths.
 */
function drawLink(start, end, color, opacity) {
  const points = [start, end];
  const geo = new THREE.BufferGeometry().setFromPoints(points);
  const mat = new THREE.LineBasicMaterial({
    color: color,
    transparent: true,
    opacity: opacity
  });
  const line = new THREE.Line(geo, mat);
  connectionsGroup.add(line);
}

/**
 * Draws a glowing Bezier curve representing correlated taint execution paths.
 */
function drawBezierCurve(start, end, color, opacity) {
  // Compute mid point and pull outwards to create a nice curve arc
  const mid = new THREE.Vector3().addVectors(start, end).multiplyScalar(0.5);
  mid.z += 1.2; // project outwards in depth
  mid.y += 0.5; // slight height arc

  const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
  const points = curve.getPoints(32);
  const geo = new THREE.BufferGeometry().setFromPoints(points);
  
  const mat = new THREE.LineBasicMaterial({
    color: color,
    transparent: true,
    opacity: opacity,
    linewidth: 1.5
  });
  const line = new THREE.Line(geo, mat);
  connectionsGroup.add(line);
}

/**
 * Three.js Animation/Render loop.
 */
function animate() {
  animationFrameId = requestAnimationFrame(animate);

  if (renderer && scene && camera) {
    const time = Date.now() * 0.001;

    // Slowly rotate the central epicenter rings
    if (epicenterGroup) {
      epicenterGroup.rotation.z = time * 0.12;
      epicenterGroup.rotation.y = Math.sin(time * 0.08) * 0.15;
    }

    // Slowly drift/rotate the constellation network
    if (nodesGroup) {
      nodesGroup.rotation.y = Math.sin(time * 0.04) * 0.1;
      nodesGroup.rotation.x = Math.cos(time * 0.02) * 0.05;
      
      // Pulse nodes slightly
      nodesGroup.children.forEach((node, i) => {
        const pulse = 1.0 + Math.sin(time * 2.5 + i) * 0.06;
        // Keep hovered nodes larger
        if (node !== hoveredNode) {
          node.scale.set(pulse, pulse, pulse);
        }
      });
    }

    // Slowly drift connection links to match node movements
    if (connectionsGroup) {
      connectionsGroup.rotation.y = nodesGroup.rotation.y;
      connectionsGroup.rotation.x = nodesGroup.rotation.x;
    }

    // Slowly rotate the digital dust particle system
    if (particles) {
      particles.rotation.y = -time * 0.025;
      particles.rotation.x = Math.sin(time * 0.01) * 0.05;
    }

    renderer.render(scene, camera);
  }
}
