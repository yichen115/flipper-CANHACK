import * as THREE from "three";

// Small rear-facing views of the same world. Hidden mirrors allocate no WebGL
// context; visible mirrors render at 20 fps and a bounded pixel budget.
export function createRearViewMirrors(scene, roots) {
  const views = [...roots].map(root => {
    const side = root.dataset.mirror === "left" ? -1 : 1;
    const camera = new THREE.PerspectiveCamera(48, 2, 0.1, 3200);
    camera.position.set(1.85 + side * 1.05, 1.4, 8.3);
    camera.lookAt(1.85 + side * 17, .8, 125);
    return { root, camera, renderer: null, visible: false };
  });
  let elapsed = 1;
  let dirty = true;

  function resize() {
    for (const view of views) {
      const width = view.root.clientWidth;
      const height = view.root.clientHeight;
      view.visible = width > 0 && height > 0;
      if (!view.visible) continue;
      if (!view.renderer) {
        view.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
        view.renderer.setPixelRatio(1);
        view.renderer.outputColorSpace = THREE.SRGBColorSpace;
        view.renderer.toneMapping = THREE.ACESFilmicToneMapping;
        view.renderer.toneMappingExposure = 1.04;
        view.root.appendChild(view.renderer.domElement);
      }
      const scale = Math.min(1.25, 360 / width);
      view.renderer.setSize(Math.round(width * scale), Math.round(height * scale), false);
      view.camera.aspect = width / height;
      view.camera.updateProjectionMatrix();
    }
    dirty = true;
  }

  const observer = new ResizeObserver(resize);
  for (const view of views) observer.observe(view.root);
  return {
    resize,
    render(delta, moving) {
      elapsed += delta;
      dirty ||= moving;
      if (!dirty || elapsed < 1 / 20 || !views.some(view => view.visible)) return;
      for (const view of views) {
        if (view.visible) view.renderer.render(scene, view.camera);
      }
      elapsed = 0;
      dirty = false;
    },
    dispose() {
      observer.disconnect();
      for (const view of views) {
        view.renderer?.dispose();
        view.renderer?.domElement.remove();
      }
    },
  };
}
