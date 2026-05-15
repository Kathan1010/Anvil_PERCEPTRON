import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';

export function initThreeScene() {
  const container = document.getElementById('three-container');
  if (!container) return;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(60, container.clientWidth / container.clientHeight, 0.1, 1000);
  camera.position.z = 25;

  const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'high-performance' });
  renderer.setSize(container.clientWidth, container.clientHeight);
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setClearColor(0x000000, 0);
  container.appendChild(renderer.domElement);

  // Lighting
  const ambientLight = new THREE.AmbientLight(0xffffff, 0.3);
  scene.add(ambientLight);
  const purpleLight = new THREE.PointLight(0xd946ef, 2, 50);
  purpleLight.position.set(5, 5, 10);
  scene.add(purpleLight);
  const cyanLight = new THREE.PointLight(0x06b6d4, 1.5, 50);
  cyanLight.position.set(-5, -3, 8);
  scene.add(cyanLight);

  // Core group
  const coreGroup = new THREE.Group();
  scene.add(coreGroup);

  // Starfield / Neural Particles
  const pGeo = new THREE.BufferGeometry();
  const pCount = 1500;
  const pPos = new Float32Array(pCount * 3);
  for (let i = 0; i < pCount * 3; i++) {
    pPos[i] = (Math.random() - 0.5) * 60; // Spread wide across the background
  }
  pGeo.setAttribute('position', new THREE.BufferAttribute(pPos, 3));
  const particles = new THREE.Points(pGeo, new THREE.PointsMaterial({
    color: 0xd946ef, size: 0.08, transparent: true, opacity: 0.6,
    blending: THREE.AdditiveBlending
  }));
  coreGroup.add(particles);

  // Add some secondary cyan particles
  const pGeo2 = new THREE.BufferGeometry();
  const pCount2 = 1000;
  const pPos2 = new Float32Array(pCount2 * 3);
  for (let i = 0; i < pCount2 * 3; i++) {
    pPos2[i] = (Math.random() - 0.5) * 60;
  }
  pGeo2.setAttribute('position', new THREE.BufferAttribute(pPos2, 3));
  const particles2 = new THREE.Points(pGeo2, new THREE.PointsMaterial({
    color: 0x06b6d4, size: 0.05, transparent: true, opacity: 0.4,
    blending: THREE.AdditiveBlending
  }));
  coreGroup.add(particles2);

  coreGroup.position.set(0, 0, 0);

  // Mouse interaction
  let mouseX = 0, mouseY = 0;
  document.addEventListener('mousemove', e => {
    mouseX = (e.clientX / window.innerWidth - 0.5) * 2;
    mouseY = (e.clientY / window.innerHeight - 0.5) * 2;
  });

  // Resize
  const onResize = () => {
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
  };
  window.addEventListener('resize', onResize);

  // Scroll-driven transforms
  let scrollY = 0;
  window.addEventListener('scroll', () => { scrollY = window.scrollY; });

  // Animation loop
  const tick = () => {
    const t = performance.now() * 0.001;

    // Mouse parallax
    coreGroup.rotation.y += (mouseX * 0.3 - coreGroup.rotation.y) * 0.02;
    coreGroup.rotation.x += (-mouseY * 0.2 - coreGroup.rotation.x) * 0.02;

    // Scroll-driven scale & position (more subtle for global background)
    const scrollProgress = scrollY / document.body.scrollHeight;
    coreGroup.position.z = scrollProgress * 15; // Move through the particles
    coreGroup.rotation.z = scrollProgress * 0.5;

    // Animate elements
    // Pulse lights
    purpleLight.intensity = 2 + Math.sin(t * 1.5) * 0.5;
    cyanLight.intensity = 1.5 + Math.cos(t * 1.2) * 0.3;

    let scrollSpeed = 1;
    if (window.lenis) {
      scrollSpeed = 1 + Math.abs(window.lenis.velocity) * 0.08;
    }
    particles.rotation.y -= 0.001 * scrollSpeed;
    particles.rotation.x += 0.0005 * scrollSpeed;
    
    if (typeof particles2 !== 'undefined') {
      particles2.rotation.y += 0.0008 * scrollSpeed;
      particles2.rotation.x -= 0.0003 * scrollSpeed;
    }

    renderer.render(scene, camera);
    requestAnimationFrame(tick);
  };
  tick();
}
