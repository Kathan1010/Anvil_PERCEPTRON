// KAVACH — Main Entry Point
import { initSmoothScroll } from './js/smooth-scroll.js';
import { initCursor, initMagnetic } from './js/cursor.js';
import { initAnimations } from './js/animations.js';
import { initThreeScene } from './js/three-scene.js';
import { initDisintegration } from './js/disintegrate.js';
import { runPipeline, resetUI, initPreviewStream } from './js/soc-engine.js';

document.addEventListener('DOMContentLoaded', () => {
  // Initialize Lucide icons
  if (typeof lucide !== 'undefined') {
    lucide.createIcons();
  }

  // Smooth scroll
  const lenis = initSmoothScroll();

  // Custom cursor
  initCursor();
  initMagnetic();

  // GSAP Animations
  initAnimations(lenis);

  // Three.js 3D scene (now background)
  initThreeScene();

  // Video disintegration effect
  initDisintegration();

  // Hero preview stream
  initPreviewStream();

  // Demo scenario buttons
  document.querySelectorAll('[data-scenario]').forEach(btn => {
    btn.addEventListener('click', () => {
      const scenario = btn.dataset.scenario;
      if (scenario) runPipeline(scenario);
    });
  });

  // FAQ Accordion
  document.querySelectorAll('.faq-question').forEach(q => {
    q.addEventListener('click', () => {
      const item = q.closest('.faq-item');
      const isOpen = item.classList.contains('open');
      // Close all
      document.querySelectorAll('.faq-item').forEach(i => i.classList.remove('open'));
      // Toggle current
      if (!isOpen) item.classList.add('open');
    });
  });

  // Navbar scroll effect
  const navbar = document.querySelector('.floating-nav');
  if (navbar) {
    window.addEventListener('scroll', () => {
      navbar.classList.toggle('scrolled', window.scrollY > 60);
    });
  }

  // Mobile menu toggle
  const mobileToggle = document.getElementById('mobile-toggle');
  const mobileMenu = document.getElementById('mobile-menu');
  if (mobileToggle && mobileMenu) {
    mobileToggle.addEventListener('click', () => {
      mobileToggle.classList.toggle('open');
      mobileMenu.classList.toggle('active');
      document.body.style.overflow = mobileMenu.classList.contains('active') ? 'hidden' : '';
    });
    mobileMenu.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        mobileToggle.classList.remove('open');
        mobileMenu.classList.remove('active');
        document.body.style.overflow = '';
      });
    });
  }

  // Scroll reveal for narrative sections
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('revealed');
      }
    });
  }, { threshold: 0.15, rootMargin: '0px 0px -50px 0px' });

  document.querySelectorAll('.reveal-on-scroll').forEach(el => {
    revealObserver.observe(el);
  });
});

