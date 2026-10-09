import * as THREE from "three";
import { createRearViewMirrors } from "./rear-view-mirrors.js";

// All scenery is generated locally. No remote models or image services are needed.
export function createDrivingScene(root, readSpeed) {
  const scene = new THREE.Scene();
  scene.fog = new THREE.Fog(0xc3c9bb, 120, 710);
  const camera = new THREE.PerspectiveCamera(57, 1, 0.1, 3200);
  // A fixed eye point in the right lane. Speed never changes the camera pose.
  camera.position.set(1.85, 1.65, 8);
  camera.lookAt(1.85, 0.3, -70);

  const renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: "high-performance" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.12;
  root.appendChild(renderer.domElement);

  scene.add(new THREE.HemisphereLight(0xc5d8e5, 0x706447, 1.9));
  const sunlight = new THREE.DirectionalLight(0xffe1a2, 2.6);
  sunlight.position.set(-65, 48, -90);
  scene.add(sunlight);
  addAtmosphere(scene);
  addMountains(scene);

  const anisotropy = Math.min(8, renderer.capabilities.getMaxAnisotropy());
  const surfaceLength = 90;
  const surfaceCount = 24;
  const scenerySpan = 720;
  const loopLength = scenerySpan * 2;
  const recycleAt = scenerySpan + 30;
  const moving = [];
  const asphalt = surfaceTexture("road");
  asphalt.repeat.set(1, surfaceLength / 15);
  asphalt.anisotropy = anisotropy;
  const grass = surfaceTexture("grass");
  grass.repeat.set(60, surfaceLength / 30);
  grass.anisotropy = anisotropy;
  const gravel = surfaceTexture("gravel");
  gravel.repeat.set(3, surfaceLength / 10);
  gravel.anisotropy = anisotropy;

  // Move textured ground geometry with the scenery. Surface UVs remain attached
  // to the ground, so road grain, tree shadows and lane markings cannot drift.
  // Each tile contains whole texture repeats; recycle it only after its rear
  // edge has passed the camera, with the far seam hidden beyond the fog.
  function addSurface(width, material, x, y) {
    const mesh = instances(scene, new THREE.PlaneGeometry(width, surfaceLength), material, surfaceCount);
    const rows = Array.from({ length: surfaceCount }, (_, index) => ({ x, y, z: recycleAt - surfaceLength / 2 - index * surfaceLength }));
    moving.push({ mesh, rows, flat: true, loopLength: surfaceCount * surfaceLength, recycleAt: recycleAt + surfaceLength / 2 });
  }
  addSurface(1800, new THREE.MeshStandardMaterial({ map: grass, roughness: 1 }), 0, -0.055);
  addSurface(11, new THREE.MeshStandardMaterial({ map: gravel, color: 0xc2b79c, roughness: 1 }), 0, -0.025);
  addSurface(7.8, new THREE.MeshStandardMaterial({ map: asphalt, roughness: 0.96, bumpMap: asphalt, bumpScale: 0.006 }), 0, 0);

  const paint = new THREE.MeshStandardMaterial({ color: 0xe0dfcc, roughness: 0.82 });
  for (const side of [-1, 1]) addSurface(0.105, paint, side * 3.55, 0.012);
  const laneMarks = instances(scene, new THREE.PlaneGeometry(0.12, 3), paint, 160);
  const markRows = Array.from({ length: 80 }, (_, i) => ({ x: 0, y: 0.014, z: 22 - i * 9 }));
  moving.push({ mesh: laneMarks, rows: markRows, flat: true });

  const metal = new THREE.MeshStandardMaterial({ color: 0xb1b7ad, metalness: 0.65, roughness: 0.47 });
  const darkMetal = new THREE.MeshStandardMaterial({ color: 0x787f77, metalness: 0.48, roughness: 0.67 });
  const railShape = new THREE.Shape();
  [[0, 0], [0.045, 0.07], [0, 0.135], [0.045, 0.2], [0, 0.27], [-0.025, 0.27], [0.02, 0.2], [-0.025, 0.135], [0.02, 0.07], [-0.025, 0]].forEach(([x, y], index) => index ? railShape.lineTo(x, y) : railShape.moveTo(x, y));
  const railGeometry = new THREE.ExtrudeGeometry(railShape, { depth: 1480, bevelEnabled: false, steps: 1 });
  for (const side of [-1, 1]) {
    const rail = new THREE.Mesh(railGeometry, metal);
    rail.position.set(side * 5.1, 0.48, -730);
    scene.add(rail);
  }
  const supports = instances(scene, new THREE.BoxGeometry(0.085, 0.73, 0.11), darkMetal, 480);
  const reflectors = instances(scene, new THREE.BoxGeometry(0.065, 0.075, 0.14), new THREE.MeshStandardMaterial({ color: 0xffdca1, emissive: 0x6a3812, emissiveIntensity: 0.2 }), 160);
  moving.push({ mesh: supports, rows: Array.from({ length: 240 }, (_, i) => ({ x: (i % 2 ? -1 : 1) * 5.14, y: 0.36, z: 24 - Math.floor(i / 2) * 6 })) });
  moving.push({ mesh: reflectors, rows: Array.from({ length: 80 }, (_, i) => ({ x: (i % 2 ? -1 : 1) * 5.07, y: 0.66, z: 24 - Math.floor(i / 2) * 18 })) });

  const rng = seededRandom(6183);
  const treeTextures = [treeTexture(46), treeTexture(137), coniferTexture(894)];
  const treeRows = Array.from({ length: 228 }, (_, index) => {
    const near = index < 80;
    return {
      x: (index % 2 ? -1 : 1) * (near ? 8.5 + rng() * 9 : 24 + rng() * 85),
      y: 0, z: 18 - rng() * scenerySpan,
      height: 7 + rng() * (near ? 5 : 10), width: 5 + rng() * 4,
      phase: rng() * Math.PI, variant: index % 3,
    };
  });
  for (let variant = 0; variant < 3; variant += 1) {
    const rows = treeRows.filter(tree => tree.variant === variant);
    const material = new THREE.MeshBasicMaterial({ map: treeTextures[variant], side: THREE.DoubleSide, alphaTest: 0.45, color: 0xf0e9cf });
    const geometry = new THREE.PlaneGeometry(1, 1).translate(0, 0.5, 0);
    const trees = instances(scene, geometry, material, rows.length * 8);
    rows.forEach((_, index) => {
      const tint = new THREE.Color().setHSL(0.11 + rng() * 0.04, 0.18 + rng() * 0.15, 0.6 + rng() * 0.22);
      for (let face = 0; face < 4; face += 1) {
        trees.setColorAt(index * 4 + face, tint);
        trees.setColorAt((index + rows.length) * 4 + face, tint);
      }
    });
    moving.push({ mesh: trees, rows, tree: true });
  }

  // Ground projections give trees contact and break up the perfectly flat road.
  const shadowMap = shadowTexture();
  const shadowRows = treeRows.filter(tree => Math.abs(tree.x) < 20);
  const shadows = instances(scene, new THREE.PlaneGeometry(1, 1), new THREE.MeshBasicMaterial({ map: shadowMap, transparent: true, depthWrite: false, polygonOffset: true, polygonOffsetFactor: -1 }), shadowRows.length * 2);
  moving.push({ mesh: shadows, rows: shadowRows.map(tree => ({ x: tree.x + 4.5, y: 0.022, z: tree.z + 3, width: tree.width * 2.8, height: tree.height * 0.65, phase: -0.7 })), flat: true, scaled: true });

  const vergeTexture = grassTexture();
  const verge = instances(scene, new THREE.PlaneGeometry(1, 1).translate(0, 0.5, 0), new THREE.MeshBasicMaterial({ map: vergeTexture, alphaTest: 0.4, side: THREE.DoubleSide, color: 0xe9dcac }), 1040);
  moving.push({ mesh: verge, rows: Array.from({ length: 520 }, (_, i) => ({ x: (i % 2 ? -1 : 1) * (5.65 + rng() * 9), y: 0, z: 20 - rng() * scenerySpan, width: 1.2 + rng() * 2, height: 0.35 + rng() * 0.65, phase: rng() * Math.PI })), scaled: true });

  // Low shrubs fill the gap between the grass verge and the tree line.
  const bushes = instances(scene, new THREE.PlaneGeometry(1, 1).translate(0, 0.5, 0), new THREE.MeshBasicMaterial({ map: bushTexture(), alphaTest: 0.45, side: THREE.DoubleSide, color: 0xe4e8c8 }), 168);
  moving.push({ mesh: bushes, rows: Array.from({ length: 84 }, (_, i) => ({ x: (i % 2 ? -1 : 1) * (6.6 + rng() * 8.5), y: 0, z: 18 - rng() * scenerySpan, width: 1.3 + rng() * 1.6, height: 0.8 + rng() * 1.1, phase: rng() * Math.PI })), scaled: true });

  // Weathered rocks scattered over the grass keep the fields from feeling empty.
  const rocks = instances(scene, new THREE.IcosahedronGeometry(1, 0), new THREE.MeshStandardMaterial({ color: 0xa39d90, roughness: 0.95, flatShading: true }), 144);
  for (let i = 0; i < 144; i += 1) rocks.setColorAt(i, new THREE.Color().setHSL(0.09, 0.05 + rng() * 0.08, 0.52 + rng() * 0.2));
  moving.push({ mesh: rocks, rows: Array.from({ length: 72 }, (_, i) => {
    const width = 0.3 + rng() * 1.3;
    return { x: (i % 2 ? -1 : 1) * (7.5 + rng() * 55), y: -0.05 - rng() * 0.15, z: 18 - rng() * scenerySpan, width, height: width * (0.5 + rng() * 0.4), depth: width * (0.7 + rng() * 0.6), phase: rng() * Math.PI, tilt: (rng() - 0.5) * 0.6 };
  }), solid: true });

  // Hectometre posts march along the right edge, just inside the guardrail.
  const postRows = Array.from({ length: 8 }, (_, i) => ({ x: 4.62, y: 0, z: 20 - i * 90, phase: -0.08 }));
  const posts = instances(scene, new THREE.BoxGeometry(0.14, 1.05, 0.1).translate(0, 0.525, 0), new THREE.MeshStandardMaterial({ color: 0xe8e6da, roughness: 0.7 }), 16);
  const bands = instances(scene, new THREE.BoxGeometry(0.15, 0.16, 0.11).translate(0, 0.95, 0), new THREE.MeshStandardMaterial({ color: 0xa83c2e, roughness: 0.6 }), 16);
  moving.push({ mesh: posts, rows: postRows.map(row => ({ ...row })) });
  moving.push({ mesh: bands, rows: postRows });

  // A power line follows the road down the left side of the valley.
  const wood = new THREE.MeshStandardMaterial({ color: 0x6b5844, roughness: 0.9 });
  const poleRows = Array.from({ length: 16 }, (_, i) => ({ x: -10.6, y: 0, z: 14 - i * 45 }));
  const poles = instances(scene, new THREE.CylinderGeometry(0.08, 0.12, 7.6, 8).translate(0, 3.8, 0), wood, 32);
  const crossarms = instances(scene, new THREE.BoxGeometry(1.7, 0.09, 0.09), wood, 32);
  const wires = instances(scene, new THREE.BoxGeometry(0.025, 0.025, 45), new THREE.MeshBasicMaterial({ color: 0x2b2e2c }), 64);
  moving.push({ mesh: poles, rows: poleRows.map(row => ({ ...row })) });
  moving.push({ mesh: crossarms, rows: poleRows.map(row => ({ x: row.x, y: 6.9, z: row.z })) });
  moving.push({ mesh: wires, rows: poleRows.flatMap(row => [-0.78, 0.78].map(offset => ({ x: row.x + offset, y: 6.82, z: row.z - 22.5 }))) });

  // Retain the road already passed for the mirror cameras. Both halves belong
  // to the same moving world; objects recycle only beyond the rear fog.
  for (const batch of moving) {
    if (!batch.loopLength) batch.rows.push(...batch.rows.map(row => ({ ...row, z: row.z + scenerySpan })));
  }

  const signs = [];
  for (const [z, kind] of [[-90, "speed"], [-310, "direction"], [-570, "speed"]]) {
    const sign = roadSign(kind);
    sign.position.set(6.6, 0, z);
    scene.add(sign);
    signs.push(sign);
    const rearSign = sign.clone();
    rearSign.position.z += scenerySpan;
    scene.add(rearSign);
    signs.push(rearSign);
  }

  // Oncoming traffic and distant wind turbines keep the world alive even while parked.
  const rotors = addWindTurbines(scene);
  const traffic = buildTraffic(scene, rng);

  const matrix = new THREE.Object3D();
  function advance(travel) {
    // A single world-space displacement drives every nearby surface and object.
    for (const batch of moving) {
      batch.rows.forEach((row, index) => {
        row.z += travel;
        if (row.z > (batch.recycleAt ?? recycleAt)) row.z -= batch.loopLength ?? loopLength;
        matrix.position.set(row.x, row.y, row.z);
        matrix.scale.set(batch.tree || batch.scaled || batch.solid ? row.width : 1, batch.tree || batch.scaled || batch.solid ? row.height : 1, batch.solid ? row.depth ?? row.width : 1);
        if (batch.tree) {
          for (let face = 0; face < 4; face += 1) {
            matrix.rotation.set(0, row.phase + face * Math.PI / 2, 0);
            matrix.updateMatrix();
            batch.mesh.setMatrixAt(index * 4 + face, matrix.matrix);
          }
        } else {
          matrix.rotation.set(batch.flat ? -Math.PI / 2 : row.tilt || 0, batch.flat ? 0 : row.phase || 0, batch.flat ? row.phase || 0 : row.roll || 0);
          matrix.updateMatrix();
          batch.mesh.setMatrixAt(index, matrix.matrix);
        }
      });
      batch.mesh.instanceMatrix.needsUpdate = true;
    }
    for (const sign of signs) {
      sign.position.z += travel;
      if (sign.position.z > recycleAt) sign.position.z -= loopLength;
    }
  }

  advance(0);
  const mirrors = createRearViewMirrors(scene, root.parentElement.querySelectorAll(".mirror-glass"));
  function resize() {
    const width = Math.max(1, root.clientWidth);
    const height = Math.max(1, root.clientHeight);
    camera.aspect = width / height;
    camera.updateProjectionMatrix();
    renderer.setSize(width, height, false);
    mirrors.resize();
    // Resizing clears the drawing buffer. Paint immediately so entering or
    // leaving fullscreen never exposes a blank windshield between frames.
    renderer.render(scene, camera);
  }
  const observer = new ResizeObserver(resize);
  observer.observe(root);
  resize();
  const clock = new THREE.Clock();
  let frame;
  function draw() {
    frame = requestAnimationFrame(draw);
    const delta = Math.min(clock.getDelta(), 0.06);
    const travel = Math.max(0, readSpeed(delta)) / 3.6 * delta;
    if (travel > 0) advance(travel);
    updateTraffic(traffic, delta, travel, rng);
    for (const rotor of rotors) rotor.rotation.z += delta * 0.55;
    renderer.render(scene, camera);
    // Traffic and turbines animate even at standstill, so mirrors stay live.
    mirrors.render(delta, true);
  }
  draw();
  if (root.dataset.debug !== undefined) window.__scene = { scene, camera, renderer, THREE };
  return {
    resize,
    dispose() {
      cancelAnimationFrame(frame);
      observer.disconnect();
      mirrors.dispose();
      const geometries = new Set(), materials = new Set(), textures = new Set();
      scene.traverse(object => {
        if (object.geometry) geometries.add(object.geometry);
        if (object.material) materials.add(object.material);
      });
      materials.forEach(material => Object.values(material).forEach(value => { if (value?.isTexture) textures.add(value); }));
      textures.forEach(texture => texture.dispose());
      materials.forEach(material => material.dispose());
      geometries.forEach(geometry => geometry.dispose());
      renderer.dispose();
      renderer.domElement.remove();
    },
  };
}

function addAtmosphere(scene) {
  const sky = new THREE.Mesh(new THREE.SphereGeometry(2400, 32, 16), new THREE.ShaderMaterial({
    side: THREE.BackSide, depthWrite: false,
    uniforms: {
      zenith: { value: new THREE.Color("#5084ab") },
      horizon: { value: new THREE.Color("#e8d7b9") },
      sunColor: { value: new THREE.Color("#ffedca") },
    },
    vertexShader: `varying vec3 vPosition;
      void main() { vPosition = position; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`,
    fragmentShader: `varying vec3 vPosition;
      uniform vec3 zenith, horizon, sunColor;
      float hash(vec2 p) { return fract(sin(dot(p, vec2(127.1, 311.7))) * 43758.5453); }
      float noise(vec2 p) {
        vec2 i = floor(p), f = fract(p); f = f * f * (3.0 - 2.0 * f);
        return mix(mix(hash(i), hash(i + vec2(1., 0.)), f.x), mix(hash(i + vec2(0., 1.)), hash(i + 1.), f.x), f.y);
      }
      float fbm(vec2 p) { float n = 0., a = .5; for(int i = 0; i < 5; i++) { n += noise(p) * a; p = p * 2.03 + 7.1; a *= .5; } return n; }
      void main() {
        vec3 d = normalize(vPosition);
        float height = max(d.y, 0.);
        vec3 color = mix(horizon, zenith, pow(smoothstep(0., .58, height), .48));
        vec3 sun = normalize(vec3(-.4, .24, -1.));
        float alignment = max(dot(d, sun), 0.);
        color += sunColor * pow(alignment, 18.) * .17;
        color += sunColor * pow(alignment, 240.) * .3;
        color += sunColor * smoothstep(.9999, .99997, alignment) * 2.;
        vec2 uv = d.xz / max(.12, d.y) * 1.8;
        float clouds = smoothstep(.48, .79, fbm(uv * vec2(.6, 1.8))) * smoothstep(.015, .18, height);
        color = mix(color, sunColor * .92, clouds * .35);
        gl_FragColor = vec4(color, 1.);
        #include <tonemapping_fragment>
        #include <colorspace_fragment>
      }`,
  }));
  sky.renderOrder = -10;
  scene.add(sky);
}

function addMountains(scene) {
  // Distant terrain stays on the horizon; only nearby scenery is recycled.
  for (let layer = 0; layer < 3; layer += 1) {
    const geometry = new THREE.PlaneGeometry(3200, 650, 200, 48);
    geometry.rotateX(-Math.PI / 2);
    const vertices = geometry.attributes.position;
    for (let index = 0; index < vertices.count; index += 1) {
      const x = vertices.getX(index), z = vertices.getZ(index);
      const ridge = Math.sin((z + 325) / 650 * Math.PI);
      const profile = 65 + 27 * Math.sin(x * .007 + layer * 2) + 19 * Math.sin(x * .016 + z * .006 + 1.7) + 7 * Math.cos(x * .051 + z * .03) + 3 * Math.sin(x * .12 + z * .08);
      const valley = 0.3 + 0.7 * Math.min(1, Math.abs(x - 90) / 450);
      vertices.setY(index, Math.max(0, ridge) * profile * valley * (.85 + layer * .35));
    }
    geometry.computeVertexNormals();
    const colors = [];
    const base = new THREE.Color([0x84948a, 0xa0afa8, 0xb8c3bd][layer]);
    for (let index = 0; index < vertices.count; index += 1) {
      const shade = .82 + Math.max(0, geometry.attributes.normal.getX(index) * -.5 + geometry.attributes.normal.getY(index) * .7) * .2;
      colors.push(base.r * shade, base.g * shade, base.b * shade);
    }
    geometry.setAttribute("color", new THREE.Float32BufferAttribute(colors, 3));
    const mountain = new THREE.Mesh(geometry, new THREE.MeshBasicMaterial({ vertexColors: true, fog: false }));
    mountain.position.set(0, -5 + layer * 4, -920 - layer * 340);
    scene.add(mountain);
  }
}

function instances(scene, geometry, material, count) {
  const mesh = new THREE.InstancedMesh(geometry, material, count);
  mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
  mesh.frustumCulled = false;
  scene.add(mesh);
  return mesh;
}

function canvasTexture(width, height, draw) {
  const canvas = document.createElement("canvas");
  canvas.width = width; canvas.height = height;
  draw(canvas.getContext("2d"), width, height);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function surfaceTexture(kind) {
  const texture = canvasTexture(512, 512, (ctx, width, height) => {
    const rng = seededRandom(kind === "road" ? 718 : kind === "grass" ? 921 : 437);
    const image = ctx.createImageData(width, height);
    const base = kind === "road" ? [64, 66, 64] : kind === "grass" ? [109, 117, 74] : [141, 131, 110];
    for (let y = 0; y < height; y += 1) {
      for (let x = 0; x < width; x += 1) {
        const i = (y * width + x) * 4;
        const grain = (rng() - .5) * (kind === "road" ? 18 : 32);
        const u = x / width * Math.PI * 2, v = y / height * Math.PI * 2;
        // Smooth, tileable variation gives the eye visible ground motion without
        // introducing high-contrast stripes or flickering fine detail.
        const mottling = Math.sin(u + .65 * Math.sin(v)) * Math.cos(v + .45 * Math.sin(2 * u))
          + .45 * Math.sin(3 * u - 2 * v + 1.2) + .3 * Math.cos(2 * u + 3 * v + .7);
        const patch = mottling * (kind === "grass" ? 12 : kind === "road" ? 5 : 8);
        let tracks = 0;
        if (kind === "road") {
          const across = x / width;
          // Wheel paths darken each lane; a faint oily strip marks lane centers.
          for (const c of [0.147, 0.353, 0.647, 0.853]) tracks -= 7.5 * Math.exp(-Math.pow((across - c) / 0.03, 2));
          for (const c of [0.25, 0.75]) tracks -= 4 * Math.exp(-Math.pow((across - c) / 0.013, 2));
          tracks -= 4 * Math.pow(Math.sin(u * 2), 12) * (.75 + .25 * Math.cos(v));
        }
        for (let c = 0; c < 3; c += 1) image.data[i + c] = base[c] + grain + patch + tracks;
        image.data[i + 3] = 255;
      }
    }
    ctx.putImageData(image, 0, 0);
    if (kind === "road") {
      ctx.strokeStyle = "#272b292b";
      ctx.lineWidth = .7;
      for (let i = 0; i < 5; i += 1) {
        let x = rng() * width, y = rng() * height;
        ctx.beginPath(); ctx.moveTo(x, y);
        for (let n = 0; n < 7; n += 1) { x += (rng() - .5) * 19; y += rng() * 9; ctx.lineTo(x, y); }
        ctx.stroke();
      }
      // Tar repair seams snake along the wheel paths.
      ctx.strokeStyle = "rgba(22, 24, 23, .5)";
      for (const start of [75, 181, 331, 437]) {
        ctx.lineWidth = 1.8 + rng() * 1.4;
        ctx.beginPath();
        let x = start + (rng() - .5) * 12;
        ctx.moveTo(x, -6);
        for (let y = 0; y <= height + 6; y += 30) { x += (rng() - .5) * 9; ctx.lineTo(x, y); }
        ctx.stroke();
      }
    }
    if (kind === "grass") {
      // Bare patches and wildflowers keep the field from reading as flat carpet.
      for (let i = 0; i < 6; i += 1) {
        const x = rng() * width, y = rng() * height, r = 16 + rng() * 38;
        const bare = ctx.createRadialGradient(x, y, 2, x, y, r);
        bare.addColorStop(0, "rgba(124, 104, 74, .42)");
        bare.addColorStop(1, "rgba(124, 104, 74, 0)");
        ctx.fillStyle = bare;
        ctx.beginPath(); ctx.ellipse(x, y, r, r * .55, rng() * 3, 0, Math.PI * 2); ctx.fill();
      }
      const petals = ["#e6e2d4", "#e3d267", "#c8d4e2"];
      for (let i = 0; i < 90; i += 1) {
        ctx.fillStyle = petals[Math.floor(rng() * 3)];
        ctx.fillRect(rng() * width, rng() * height, 1.6, 1.6);
      }
    }
  });
  texture.wrapS = texture.wrapT = THREE.RepeatWrapping;
  return texture;
}

export function treeTexture(seed) {
  return canvasTexture(768, 1024, (ctx) => {
    const rng = seededRandom(seed);
    const segments = [];
    const leafPoints = [];
    function branch(x, y, angle, length, width, depth) {
      const endX = x + Math.cos(angle) * length, endY = y + Math.sin(angle) * length;
      segments.push({ x1: x, y1: y, x2: endX, y2: endY, width, depth });
      if (depth <= 4) {
        // Leaf clusters run continuously along the outer twigs, so the crown
        // reads as one connected canopy instead of stripes along each limb.
        const steps = depth <= 2 ? 5 : depth === 3 ? 2 : 1;
        for (let i = 0; i < steps; i += 1) {
          const t = depth <= 2 ? 0.15 + i * 0.21 : 0.45 + i * 0.4;
          leafPoints.push({ x: x + (endX - x) * t + (rng() - .5) * 22, y: y + (endY - y) * t + (rng() - .5) * 22, depth });
        }
      }
      if (depth === 0) return;
      const forks = depth > 4 ? 2 : rng() < .35 ? 3 : 2;
      for (let f = 0; f < forks; f += 1) {
        // Wide, irregular spreading keeps the crown broad rather than conical.
        const spread = (f - (forks - 1) / 2) * (0.55 + rng() * 0.35) + (rng() - .5) * 0.16;
        branch(endX, endY, angle + spread, length * (0.66 + rng() * 0.12), width * 0.62, depth - 1);
      }
    }
    branch(384, 1030, -Math.PI / 2, 175, 19, 6);
    // Bark first, thick limbs below thin twigs.
    for (const s of segments) {
      ctx.strokeStyle = s.depth > 3 ? "#4a4131" : "#5d5640";
      ctx.lineCap = "round";
      ctx.lineWidth = Math.max(1.2, s.width);
      ctx.beginPath(); ctx.moveTo(s.x1, s.y1); ctx.lineTo(s.x2, s.y2); ctx.stroke();
    }
    // Canopy in three passes: deep shade, mid tones, then sunlit upper-left.
    const passes = [
      { colors: ["#22301e", "#2b3a24", "#34452a"], scale: 1.18, dx: 16, dy: 18, count: 8 },
      { colors: ["#3d502e", "#4a5e36", "#566c3e"], scale: 1, dx: 0, dy: 0, count: 9 },
      { colors: ["#687c46", "#7c8e51", "#8fa05d"], scale: 0.78, dx: -13, dy: -15, count: 6 },
    ];
    leafPoints.sort((a, b) => b.y - a.y);
    for (const p of leafPoints) {
      const radius = (24 + rng() * 30) * (1 + (3 - p.depth) * 0.12);
      for (const pass of passes) {
        for (let n = 0; n < pass.count; n += 1) {
          if (rng() < 0.08) continue; // irregular gaps keep the silhouette organic
          const a = rng() * Math.PI * 2, r = Math.sqrt(rng()) * radius * pass.scale;
          const px = p.x + pass.dx + Math.cos(a) * r;
          const py = p.y + pass.dy + Math.sin(a) * r * 0.8;
          if (px < 12 || px > 756 || py < 12) continue; // keep leaves off the texture border
          ctx.fillStyle = pass.colors[Math.floor(rng() * pass.colors.length)];
          ctx.beginPath(); ctx.ellipse(px, py, 2 + rng() * 4.5, 1.4 + rng() * 3, a, 0, Math.PI * 2); ctx.fill();
        }
      }
    }
  });
}

function shadowTexture() {
  return canvasTexture(256, 256, ctx => {
    const rng = seededRandom(51);
    for (let i = 0; i < 110; i += 1) {
      const x = 128 + (rng() - .5) * 155, y = 128 + (rng() - .5) * 115;
      const gradient = ctx.createRadialGradient(x, y, 1, x, y, 22 + rng() * 22);
      gradient.addColorStop(0, "rgba(22, 32, 29, .12)");
      gradient.addColorStop(1, "rgba(22, 32, 29, 0)");
      ctx.fillStyle = gradient; ctx.fillRect(0, 0, 256, 256);
    }
  });
}

function grassTexture() {
  return canvasTexture(256, 128, ctx => {
    const rng = seededRandom(38);
    for (let i = 0; i < 95; i += 1) {
      const x = rng() * 256, height = 12 + rng() * 91;
      ctx.strokeStyle = ["#737646", "#93925b", "#5b663d", "#ae9f69"][i % 4];
      ctx.lineWidth = 1 + rng();
      ctx.beginPath(); ctx.moveTo(x, 128); ctx.quadraticCurveTo(x + 5, 128 - height * .6, x + (rng() - .5) * 35, 128 - height); ctx.stroke();
    }
  });
}

function roadSign(kind) {
  const group = new THREE.Group();
  const backing = new THREE.MeshStandardMaterial({ color: 0x9ea6a5, metalness: .65, roughness: .46 });
  const post = new THREE.Mesh(new THREE.CylinderGeometry(.035, .05, 2.6, 12), backing);
  post.position.set(0, 1.3, -.09);
  group.add(post);
  const plate = new THREE.Mesh(kind === "speed" ? new THREE.CylinderGeometry(.49, .49, .05, 64) : new THREE.BoxGeometry(2.18, 1.37, .05), backing);
  if (kind === "speed") plate.rotation.x = Math.PI / 2;
  plate.position.y = 2.6;
  group.add(plate);
  const texture = canvasTexture(512, kind === "speed" ? 512 : 320, (ctx, width, height) => {
    if (kind === "speed") {
      ctx.fillStyle = "#f4f0dd"; ctx.fillRect(0, 0, width, height);
      ctx.strokeStyle = "#b84333"; ctx.lineWidth = 38; ctx.beginPath(); ctx.arc(256, 256, 220, 0, Math.PI * 2); ctx.stroke();
      ctx.fillStyle = "#262c29"; ctx.font = "600 230px Arial"; ctx.textAlign = "center"; ctx.textBaseline = "middle"; ctx.fillText("80", 256, 275);
    } else {
      ctx.fillStyle = "#28564c"; ctx.fillRect(0, 0, width, height);
      ctx.strokeStyle = "#e0e5d0"; ctx.lineWidth = 8; ctx.strokeRect(14, 14, width - 28, height - 28);
      ctx.fillStyle = "#f1f0dd"; ctx.font = "500 54px 'Microsoft YaHei', sans-serif"; ctx.fillText("山 间 公 路", 44, 100);
      ctx.font = "28px Arial"; ctx.fillText("SCENIC ROUTE", 46, 155);
      ctx.font = "52px Arial"; ctx.fillText("↑  2 km", 46, 257);
    }
  });
  const face = new THREE.Mesh(kind === "speed" ? new THREE.CircleGeometry(.48, 64) : new THREE.PlaneGeometry(2.15, 1.34), new THREE.MeshBasicMaterial({ map: texture }));
  face.position.set(0, 2.6, .028);
  group.add(face);
  return group;
}

export function coniferTexture(seed) {
  return canvasTexture(768, 1024, (ctx) => {
    const rng = seededRandom(seed);
    // A dark core guarantees no sky shows between the needle layers.
    const core = ctx.createLinearGradient(0, 80, 0, 1000);
    core.addColorStop(0, "#2a3a2c");
    core.addColorStop(1, "#1f2c22");
    ctx.fillStyle = core;
    ctx.beginPath();
    ctx.moveTo(384, 70);
    ctx.lineTo(660, 980);
    ctx.lineTo(108, 980);
    ctx.closePath();
    ctx.fill();
    ctx.strokeStyle = "#4c4133";
    ctx.lineCap = "round";
    ctx.lineWidth = 18;
    ctx.beginPath(); ctx.moveTo(384, 1024); ctx.lineTo(384, 760); ctx.stroke();
    const colors = ["#26362a", "#31452f", "#3e5336", "#4d6340", "#5f754b"];
    // Dense, drooping needle layers from a wide base to a narrow tip.
    for (let layer = 0; layer < 30; layer += 1) {
      const y = 965 - layer * 30;
      const half = (24 + (1 - layer / 30) * 265) * (0.88 + rng() * 0.24);
      for (let n = 0; n < 80; n += 1) {
        const t = rng() * 2 - 1;
        const px = 384 + t * half;
        const py = y + Math.abs(t) * (14 + rng() * 22) + (rng() - .5) * 12;
        const light = Math.max(0, Math.min(4, Math.floor(rng() * 2 + (1 - py / 1000) * 2 + (1 - px / 768) * 1.5)));
        ctx.fillStyle = colors[light];
        ctx.beginPath(); ctx.ellipse(px, py, 3.5 + rng() * 6, 2 + rng() * 3.5, t * .7, 0, Math.PI * 2); ctx.fill();
      }
    }
  });
}

export function bushTexture() {
  return canvasTexture(512, 256, (ctx) => {
    const rng = seededRandom(517);
    // A shaded mound underneath keeps the bush opaque at its core.
    const mound = ctx.createRadialGradient(256, 250, 10, 256, 250, 235);
    mound.addColorStop(0, "#2e3c25");
    mound.addColorStop(0.72, "#37482b");
    mound.addColorStop(1, "rgba(55, 72, 43, 0)");
    ctx.fillStyle = mound;
    ctx.beginPath(); ctx.ellipse(256, 250, 235, 105, 0, 0, Math.PI * 2); ctx.fill();
    const colors = ["#3a4a2d", "#495b36", "#5a6c41", "#6d7d4d", "#7f8c58"];
    for (let n = 0; n < 1400; n += 1) {
      const a = rng() * Math.PI * 2, r = Math.sqrt(rng());
      const px = 256 + Math.cos(a) * r * 235;
      const py = 250 - Math.abs(Math.sin(a)) * r * 200 - rng() * 14;
      const light = Math.max(0, Math.min(4, Math.floor(rng() * 2.6 + (1 - py / 256) * 2)));
      ctx.fillStyle = colors[light];
      ctx.beginPath(); ctx.ellipse(px, py, 2 + rng() * 4.5, 1.5 + rng() * 3, a, 0, Math.PI * 2); ctx.fill();
    }
  });
}

function buildCar(color) {
  const group = new THREE.Group();
  const paintMaterial = new THREE.MeshStandardMaterial({ color, metalness: 0.55, roughness: 0.35 });
  const glassMaterial = new THREE.MeshStandardMaterial({ color: 0x232a30, metalness: 0.4, roughness: 0.15 });
  const darkMaterial = new THREE.MeshStandardMaterial({ color: 0x17191c, roughness: 0.85 });
  const body = new THREE.Mesh(new THREE.BoxGeometry(1.78, 0.55, 4.25), paintMaterial);
  body.position.y = 0.66;
  group.add(body);
  const cabin = new THREE.Mesh(new THREE.BoxGeometry(1.58, 0.5, 2.2), glassMaterial);
  cabin.position.set(0, 1.14, 0.3);
  group.add(cabin);
  const grille = new THREE.Mesh(new THREE.BoxGeometry(1.2, 0.16, 0.06), darkMaterial);
  grille.position.set(0, 0.62, 2.14);
  group.add(grille);
  const wheelGeometry = new THREE.CylinderGeometry(0.33, 0.33, 0.24, 18);
  wheelGeometry.rotateZ(Math.PI / 2);
  for (const [x, z] of [[-0.8, 1.32], [0.8, 1.32], [-0.8, -1.32], [0.8, -1.32]]) {
    const wheel = new THREE.Mesh(wheelGeometry, darkMaterial);
    wheel.position.set(x, 0.33, z);
    group.add(wheel);
  }
  const headlight = new THREE.MeshStandardMaterial({ color: 0xf5eeda, emissive: 0xfff3c4, emissiveIntensity: 1.1 });
  const taillight = new THREE.MeshStandardMaterial({ color: 0x7c1d17, emissive: 0xa3251b, emissiveIntensity: 0.5 });
  for (const side of [-1, 1]) {
    const front = new THREE.Mesh(new THREE.BoxGeometry(0.34, 0.13, 0.05), headlight);
    front.position.set(side * 0.6, 0.72, 2.14);
    group.add(front);
    const rear = new THREE.Mesh(new THREE.BoxGeometry(0.3, 0.11, 0.05), taillight);
    rear.position.set(side * 0.6, 0.74, -2.14);
    group.add(rear);
  }
  const shadow = new THREE.Mesh(new THREE.CircleGeometry(1.5, 24), new THREE.MeshBasicMaterial({ color: 0x11150f, transparent: true, opacity: 0.32, depthWrite: false }));
  shadow.rotation.x = -Math.PI / 2;
  shadow.scale.set(0.75, 1.65, 1);
  shadow.position.y = 0.02;
  group.add(shadow);
  return { group, body };
}

// Oncoming cars drive their own speed toward the camera on the left lane.
// Each pass recycles far beyond the fog with a fresh speed, lane offset and color.
function buildTraffic(scene, rng) {
  const palette = [0xc9ccce, 0x8a2323, 0x2c4a68, 0xdedbd2, 0x33373d, 0x707a62];
  const cars = [];
  for (let i = 0; i < 6; i += 1) {
    const car = buildCar(palette[i % palette.length]);
    scene.add(car.group);
    cars.push({ ...car, x: -1.95 + (rng() - 0.5) * 0.3, z: -60 - i * 130 - rng() * 90, speed: (55 + rng() * 35) / 3.6 });
  }
  for (const car of cars) car.group.position.set(car.x, 0, car.z);
  return { cars, palette };
}

function updateTraffic(traffic, delta, travel, rng) {
  for (const car of traffic.cars) {
    car.z += travel + car.speed * delta;
    if (car.z > 16) {
      car.z -= 950 + rng() * 420;
      car.speed = (50 + rng() * 45) / 3.6;
      car.x = -1.95 + (rng() - 0.5) * 0.3;
      car.body.material.color.setHex(traffic.palette[Math.floor(rng() * traffic.palette.length)]);
    }
    car.group.position.set(car.x, 0, car.z);
  }
}

// Slow-turning turbines stand on the far ridge, silhouetted with the mountains.
function addWindTurbines(scene) {
  const material = new THREE.MeshBasicMaterial({ color: 0xbcc6c9, fog: false });
  const rng = seededRandom(77);
  const rotors = [];
  for (const [x, z, scale] of [[-330, -850, 1.25], [-160, -880, 1.4], [40, -840, 1.15]]) {
    const turbine = new THREE.Group();
    const tower = new THREE.Mesh(new THREE.CylinderGeometry(0.9, 1.6, 62, 10), material);
    tower.position.y = 31;
    turbine.add(tower);
    const nacelle = new THREE.Mesh(new THREE.BoxGeometry(2.4, 2.4, 5), material);
    nacelle.position.y = 62;
    turbine.add(nacelle);
    const rotor = new THREE.Group();
    for (let i = 0; i < 3; i += 1) {
      const blade = new THREE.Mesh(new THREE.BoxGeometry(1.1, 26, 0.3).translate(0, 13, 0), material);
      blade.rotation.z = i * Math.PI * 2 / 3;
      rotor.add(blade);
    }
    rotor.position.set(0, 62, 2.8);
    rotor.rotation.z = rng() * Math.PI;
    turbine.add(rotor);
    rotors.push(rotor);
    turbine.scale.setScalar(scale);
    turbine.position.set(x, 8, z);
    scene.add(turbine);
  }
  return rotors;
}

function seededRandom(seed) {
  let value = seed >>> 0;
  return () => { value = (value * 1664525 + 1013904223) >>> 0; return value / 4294967296; };
}
