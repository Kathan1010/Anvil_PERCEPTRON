/**
 * KAVACH — Video Disintegration Effect
 * On scroll, the hero video "shatters" into thousands of particles
 * that float across the entire website as background ambiance.
 */

export function initDisintegration() {
  const video = document.getElementById('hero-video');
  const videoWrap = document.getElementById('hero-video-wrap');
  const canvas = document.getElementById('disintegration-canvas');
  if (!video || !canvas) return;

  const ctx = canvas.getContext('2d');

  // Sampling canvas (hidden) to read video pixels
  const samplerCanvas = document.createElement('canvas');
  const samplerCtx = samplerCanvas.getContext('2d', { willReadFrequently: true });

  // Config - optimized for performance
  const SAMPLE_SIZE = 40;       // Reduced grid resolution for faster sampling
  const PARTICLE_COUNT_MAX = 800; // Significantly reduced for performance
  const BURST_SCROLL_START = 100;
  const BURST_SCROLL_END = 600;
  const FLOAT_SPEED = 0.3;

  let particles = [];
  let sampled = false;
  let animating = false;
  let scrollY = 0;
  let width = window.innerWidth;
  let height = window.innerHeight;

  // Resize handler
  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width;
    canvas.height = height;
  }
  resize();
  window.addEventListener('resize', resize);

  // Scroll tracker
  window.addEventListener('scroll', () => { scrollY = window.scrollY; });

  // Particle class
  class Particle {
    constructor(x, y, color) {
      // Original position (where it was sampled from the video)
      this.originX = x;
      this.originY = y;
      this.x = x;
      this.y = y;
      this.color = color;
      this.size = 2 + Math.random() * 2;

      // Random target for floating
      this.floatX = Math.random() * width;
      this.floatY = Math.random() * height * 3; // Spread across full page height
      this.floatVx = (Math.random() - 0.5) * FLOAT_SPEED;
      this.floatVy = -Math.random() * FLOAT_SPEED * 0.5 - 0.1;

      // Physics
      this.burstAngle = Math.atan2(y - height / 2, x - width / 2) + (Math.random() - 0.5) * 1.5;
      this.burstSpeed = 2 + Math.random() * 4;
      this.opacity = 1;
      this.life = 0.7 + Math.random() * 0.3;
    }
  }

  // Sample video frame to create particles
  function sampleVideoFrame() {
    if (!video.videoWidth || !video.videoHeight) return false;

    const vw = video.videoWidth;
    const vh = video.videoHeight;

    // Scale sample canvas
    const sampleW = SAMPLE_SIZE;
    const sampleH = Math.round(SAMPLE_SIZE * (vh / vw));
    samplerCanvas.width = sampleW;
    samplerCanvas.height = sampleH;

    // Draw current video frame
    samplerCtx.drawImage(video, 0, 0, sampleW, sampleH);
    const imgData = samplerCtx.getImageData(0, 0, sampleW, sampleH);
    const data = imgData.data;

    particles = [];

    const scaleX = width / sampleW;
    const scaleY = height / sampleH;

    for (let y = 0; y < sampleH; y++) {
      for (let x = 0; x < sampleW; x++) {
        const i = (y * sampleW + x) * 4;
        const r = data[i];
        const g = data[i + 1];
        const b = data[i + 2];
        const a = data[i + 3];

        // Skip very dark or transparent pixels
        if (a < 50) continue;
        const brightness = (r + g + b) / 3;
        if (brightness < 15) continue;
        // Skip pure white borders (letterboxing/pillarboxing)
        if (brightness > 240 && r > 240 && g > 240 && b > 240) continue;

        // Map sample position to screen position
        const px = x * scaleX;
        const py = y * scaleY;

        particles.push(new Particle(px, py, `rgba(${r},${g},${b},1)`));

        if (particles.length >= PARTICLE_COUNT_MAX) break;
      }
      if (particles.length >= PARTICLE_COUNT_MAX) break;
    }

    return particles.length > 0;
  }

  // Animation loop
  function animate() {
    if (!animating) return;

    ctx.clearRect(0, 0, width, height);

    // Calculate disintegration progress (0 = intact, 1 = fully disintegrated)
    const progress = Math.max(0, Math.min(1, (scrollY - BURST_SCROLL_START) / (BURST_SCROLL_END - BURST_SCROLL_START)));

    if (progress <= 0) {
      canvas.style.opacity = '0';
      if (videoWrap) videoWrap.style.opacity = '1';
      requestAnimationFrame(animate);
      return;
    }

    // Control canvas and video opacity
    canvas.style.opacity = '1';
    if (videoWrap) videoWrap.style.opacity = String(1 - progress);

    // Ease function for burst
    const easeProgress = 1 - Math.pow(1 - progress, 3); // ease-out cubic

    for (let i = 0; i < particles.length; i++) {
      const p = particles[i];

      // Interpolate from origin to burst position
      const burstDist = p.burstSpeed * easeProgress * 120;
      const burstX = p.originX + Math.cos(p.burstAngle) * burstDist;
      const burstY = p.originY + Math.sin(p.burstAngle) * burstDist;

      // After burst, float gently
      const floatProgress = Math.max(0, (progress - 0.3) / 0.7);
      const floatOffsetX = p.floatVx * floatProgress * 300 + Math.sin(performance.now() * 0.001 + i) * 2;
      const floatOffsetY = p.floatVy * floatProgress * 300 + Math.cos(performance.now() * 0.0008 + i) * 1.5;

      p.x = burstX + floatOffsetX;
      p.y = burstY + floatOffsetY;

      // Particle opacity — fade slightly at full burst
      p.opacity = Math.max(0.1, p.life - easeProgress * 0.4);

      // Draw (Optimized with fillRect instead of arc for massive performance boost)
      ctx.fillStyle = p.color.replace(',1)', `,${p.opacity})`);
      const drawSize = p.size * (1 - easeProgress * 0.3);
      ctx.fillRect(p.x, p.y, drawSize, drawSize);
    }

    requestAnimationFrame(animate);
  }

  // Wait for video to be ready, then sample and start
  function tryInit() {
    if (video.readyState >= 2 && video.videoWidth > 0) {
      if (sampleVideoFrame()) {
        sampled = true;
        animating = true;
        animate();

        // Re-sample periodically to update particle colors, but only if visible
        setInterval(() => {
          if (scrollY < BURST_SCROLL_START) {
            sampleVideoFrame();
          }
        }, 5000); // Reduced frequency from 2s to 5s to save CPU
      }
    } else {
      // Retry
      setTimeout(tryInit, 300);
    }
  }

  video.addEventListener('loadeddata', tryInit);
  // Also try immediately in case video is already loaded
  setTimeout(tryInit, 500);
}

