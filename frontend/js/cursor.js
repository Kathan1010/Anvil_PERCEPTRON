import gsap from 'gsap';

export function initCursor() {
  const cursor = document.getElementById('cursor');
  if (!cursor || window.matchMedia('(pointer: coarse)').matches) return;

  const dot = cursor.querySelector('.cursor-dot');
  const ring = cursor.querySelector('.cursor-ring');
  const blob = document.getElementById('reactive-blob');
  let mx = 0, my = 0;

  window.addEventListener('mousemove', e => {
    mx = e.clientX;
    my = e.clientY;
    gsap.to(dot, { x: mx, y: my, duration: 0.1, ease: 'power2.out' });
    gsap.to(ring, { x: mx, y: my, duration: 0.25, ease: 'power2.out' });
    
    if (blob) {
      // Create a slight delay/organic feeling for the blob
      const rect = blob.parentElement.getBoundingClientRect();
      const bx = mx - rect.left;
      const by = my - rect.top;
      gsap.to(blob, { x: bx - 300, y: by - 300, duration: 2, ease: 'power3.out' });
    }
  });
}

export function initMagnetic() {
  if (window.matchMedia('(pointer: coarse)').matches) return;

  document.querySelectorAll('.magnetic').forEach(el => {
    const strength = parseFloat(el.dataset.strength) || 20;

    el.addEventListener('mousemove', e => {
      const rect = el.getBoundingClientRect();
      const cx = rect.left + rect.width / 2;
      const cy = rect.top + rect.height / 2;
      const dx = (e.clientX - cx) / rect.width * strength;
      const dy = (e.clientY - cy) / rect.height * strength;
      gsap.to(el, { x: dx, y: dy, duration: 0.3, ease: 'power2.out' });
    });

    el.addEventListener('mouseleave', () => {
      gsap.to(el, { x: 0, y: 0, duration: 0.5, ease: 'elastic.out(1, 0.5)' });
    });
  });
}
