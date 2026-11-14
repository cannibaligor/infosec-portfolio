// Small Three.js scene helper shared by the lab, replay and phishing views.
import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { CSS2DRenderer, CSS2DObject } from 'three/addons/renderers/CSS2DRenderer.js';
import { themeColors, reducedMotion } from './common.js';

export { THREE };

export function webglOK() {
  try {
    const c = document.createElement('canvas');
    return !!(window.WebGLRenderingContext && (c.getContext('webgl2') || c.getContext('webgl')));
  } catch { return false; }
}

export function createStage(wrap, canvas, { camPos = [0, 6, 11], target = [0, 0, 0], autoRotate = true, minDist = 6, maxDist = 22 } = {}) {
  const colors = themeColors();
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setClearColor(0x000000, 0);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 200);
  camera.position.set(...camPos);

  const labels = new CSS2DRenderer();
  labels.domElement.style.position = 'absolute';
  labels.domElement.style.inset = '0';
  labels.domElement.style.pointerEvents = 'none';
  wrap.appendChild(labels.domElement);

  const controls = new OrbitControls(camera, canvas);
  controls.target.set(...target);
  controls.enableDamping = true;
  controls.enablePan = false;
  controls.minDistance = minDist;
  controls.maxDistance = maxDist;
  controls.maxPolarAngle = Math.PI * 0.47;
  controls.autoRotate = autoRotate && !reducedMotion;
  controls.autoRotateSpeed = 0.5;
  // pause auto-rotate while the user interacts, resume after a while
  let resumeT;
  controls.addEventListener('start', () => { controls.autoRotate = false; clearTimeout(resumeT); });
  controls.addEventListener('end', () => {
    clearTimeout(resumeT);
    if (autoRotate && !reducedMotion) resumeT = setTimeout(() => (controls.autoRotate = true), 6000);
  });

  scene.add(new THREE.HemisphereLight(0xffffff, 0x8a8f99, 1.6));
  const dir = new THREE.DirectionalLight(0xffffff, 1.4);
  dir.position.set(5, 10, 6);
  scene.add(dir);

  const grid = new THREE.GridHelper(24, 24, new THREE.Color(colors.line), new THREE.Color(colors.line));
  grid.position.y = -0.9;
  grid.material.transparent = true;
  grid.material.opacity = 0.7;
  scene.add(grid);

  const tickers = new Set();
  const clock = new THREE.Clock();
  let visible = true;

  function resize() {
    const w = wrap.clientWidth, h = wrap.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    labels.setSize(w, h);
    camera.aspect = w / h;
    // keep the same horizontal field of view on narrow (phone) viewports
    camera.fov = camera.aspect < 1.5 ? Math.min(85, 42 * Math.pow(1.5 / camera.aspect, 0.75)) : 42;
    camera.updateProjectionMatrix();
  }
  new ResizeObserver(resize).observe(wrap);
  resize();

  new IntersectionObserver(([en]) => { visible = en.isIntersecting; }, { rootMargin: '100px' }).observe(wrap);

  renderer.setAnimationLoop(() => {
    const dt = Math.min(clock.getDelta(), 0.05);
    if (!visible) return;
    for (const t of [...tickers]) if (t(dt) === false) tickers.delete(t);
    controls.update();
    renderer.render(scene, camera);
    labels.render(scene, camera);
  });

  // --- picking -------------------------------------------------------------
  const ray = new THREE.Raycaster();
  const pickables = [];
  let downAt = null;
  canvas.addEventListener('pointerdown', e => { downAt = [e.clientX, e.clientY]; });
  canvas.addEventListener('pointerup', e => {
    if (!downAt || Math.hypot(e.clientX - downAt[0], e.clientY - downAt[1]) > 6) return;
    const hit = pick(e);
    if (hit) hit.userData.onPick?.(hit);
  });
  canvas.addEventListener('pointermove', e => {
    if (e.buttons) return;
    canvas.style.cursor = pick(e) ? 'pointer' : 'grab';
  });
  function pick(e) {
    const r = canvas.getBoundingClientRect();
    const p = new THREE.Vector2(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
    ray.setFromCamera(p, camera);
    const hits = ray.intersectObjects(pickables, true);
    if (!hits.length) return null;
    let o = hits[0].object;
    while (o && !o.userData.onPick) o = o.parent;
    return o;
  }

  return { THREE, scene, camera, renderer, controls, colors, tickers, pickables, addTick: f => tickers.add(f) };
}

/** A minimal "machine": rounded slab with an outline and a floating label. */
export function makeNode(stage, { pos, color, shape = 'box', label, sub, onPick, labelY }) {
  const { scene, colors } = stage;
  const g = new THREE.Group();
  g.position.set(...pos);
  let geo;
  if (shape === 'tower') geo = new THREE.BoxGeometry(1.1, 1.8, 1.1);
  else if (shape === 'ico') geo = new THREE.IcosahedronGeometry(0.85, 0);
  else if (shape === 'cyl') geo = new THREE.CylinderGeometry(0.75, 0.75, 1.5, 32);
  else if (shape === 'cloud') geo = new THREE.OctahedronGeometry(0.8, 0);
  else geo = new THREE.BoxGeometry(1.4, 1.0, 1.0);
  const mat = new THREE.MeshStandardMaterial({ color: new THREE.Color(colors.surface), roughness: 0.55, metalness: 0.05 });
  const mesh = new THREE.Mesh(geo, mat);
  const edgeMat = new THREE.LineBasicMaterial({ color: new THREE.Color(color) });
  const edges = new THREE.LineSegments(new THREE.EdgesGeometry(geo), edgeMat);
  mesh.add(edges);
  g.add(mesh);

  // accent band
  const band = new THREE.Mesh(new THREE.TorusGeometry(1.15, 0.025, 8, 64), new THREE.MeshBasicMaterial({ color: new THREE.Color(color), transparent: true, opacity: 0.6 }));
  band.rotation.x = Math.PI / 2;
  band.position.y = -0.85;
  g.add(band);

  const el = document.createElement('div');
  el.className = 'label3d';
  el.innerHTML = label + (sub ? `<small>${sub}</small>` : '');
  const lab = new CSS2DObject(el);
  lab.position.set(0, labelY ?? (shape === 'tower' ? 1.55 : 1.3), 0);
  g.add(lab);

  if (onPick) { g.userData.onPick = onPick; stage.pickables.push(g); }
  scene.add(g);
  const node = { group: g, mesh, edges, band, el, color, pos: new THREE.Vector3(...pos) };
  node.setColor = c => { edgeMat.color.set(c); band.material.color.set(c); };
  return node;
}

export function link(stage, a, b, { color, dashed = true, opacity = 0.6, lift = 0.6 } = {}) {
  const curve = arc(a, b, lift);
  const pts = curve.getPoints(48);
  const geo = new THREE.BufferGeometry().setFromPoints(pts);
  const mat = dashed
    ? new THREE.LineDashedMaterial({ color: new THREE.Color(color), dashSize: 0.18, gapSize: 0.12, transparent: true, opacity })
    : new THREE.LineBasicMaterial({ color: new THREE.Color(color), transparent: true, opacity });
  const line = new THREE.Line(geo, mat);
  if (dashed) line.computeLineDistances();
  stage.scene.add(line);
  return { line, curve, mat };
}

export function arc(a, b, lift = 0.6) {
  const pa = a.isVector3 ? a : a.pos, pb = b.isVector3 ? b : b.pos;
  const mid = pa.clone().add(pb).multiplyScalar(0.5);
  mid.y += lift + pa.distanceTo(pb) * 0.12;
  return new THREE.QuadraticBezierCurve3(pa.clone(), mid, pb.clone());
}

/** Fire a glowing packet along a curve. Resolves when it arrives. */
export function packet(stage, curve, { color, size = 0.13, duration = 0.9 } = {}) {
  return new Promise(resolve => {
    const m = new THREE.Mesh(new THREE.SphereGeometry(size, 16, 16), new THREE.MeshBasicMaterial({ color: new THREE.Color(color) }));
    const halo = new THREE.Mesh(new THREE.SphereGeometry(size * 2.2, 16, 16), new THREE.MeshBasicMaterial({ color: new THREE.Color(color), transparent: true, opacity: 0.18 }));
    m.add(halo);
    stage.scene.add(m);
    let t = 0;
    const d = reducedMotion ? 0.01 : duration;
    stage.addTick(dt => {
      t += dt / d;
      const k = Math.min(t, 1);
      m.position.copy(curve.getPoint(k < 0.5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2));
      if (k >= 1) {
        stage.scene.remove(m); m.geometry.dispose(); halo.geometry.dispose();
        resolve();
        return false;
      }
    });
  });
}

/** Expanding ring pulse at a position. */
export function ring(stage, pos, { color, from = 0.6, to = 2.4, duration = 1.1 } = {}) {
  if (reducedMotion) return;
  const m = new THREE.Mesh(new THREE.RingGeometry(0.92, 1, 64), new THREE.MeshBasicMaterial({ color: new THREE.Color(color), transparent: true, opacity: 0.8, side: THREE.DoubleSide }));
  m.rotation.x = -Math.PI / 2;
  m.position.copy(pos);
  m.position.y = -0.85;
  stage.scene.add(m);
  let t = 0;
  stage.addTick(dt => {
    t += dt / duration;
    const s = from + (to - from) * t;
    m.scale.set(s, s, s);
    m.material.opacity = 0.8 * (1 - t);
    if (t >= 1) { stage.scene.remove(m); m.geometry.dispose(); return false; }
  });
}

/** Little "shake" of a node (used for a rejected logon). */
export function shake(stage, node, amp = 0.08) {
  if (reducedMotion) return;
  let t = 0;
  const base = node.pos.x;
  stage.addTick(dt => {
    t += dt;
    node.group.position.x = base + Math.sin(t * 60) * amp * (1 - t / 0.35);
    if (t >= 0.35) { node.group.position.x = base; return false; }
  });
}
