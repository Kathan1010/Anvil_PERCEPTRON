import Lenis from 'lenis'

export function initSmoothScroll() {
  const lenis = new Lenis({
    lerp: 0.07, 
    wheelMultiplier: 1.2, 
    smoothWheel: true,
  });

  function raf(time) {
    lenis.raf(time);
    requestAnimationFrame(raf);
  }
  requestAnimationFrame(raf);

  window.lenis = lenis;
  return lenis;
}
