import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import SplitType from 'split-type';

gsap.registerPlugin(ScrollTrigger);

export function initAnimations(lenis) {
  if (lenis) {
    lenis.on('scroll', ScrollTrigger.update);
    gsap.ticker.add((time) => lenis.raf(time * 1000));
    gsap.ticker.lagSmoothing(0);
  }

  function splitReveal(selector) {
    const el = typeof selector === 'string' ? document.querySelector(selector) : selector;
    if (!el || el.dataset.split === 'done') return;
    el.dataset.split = 'done';
    const split = new SplitType(el, { types: 'lines,words' });
    split.lines.forEach(line => {
      const w = document.createElement('div');
      w.style.overflow = 'hidden';
      w.style.padding = '0.1em 0';
      w.style.margin = '-0.1em 0';
      line.parentNode.insertBefore(w, line);
      w.appendChild(line);
    });
    gsap.fromTo(split.words, { yPercent: 120, opacity: 0 },
      { yPercent: 0, opacity: 1, stagger: 0.03, duration: 1.2, ease: 'power4.out' });
  }

  // ===== PRELOADER SEQUENCE =====
  const loaderEl = document.getElementById('KAVACH-loader');
  const pctEl = document.getElementById('loader-pct');
  const barEl = document.getElementById('loader-bar');
  const statusEl = document.querySelector('.loader-status');
  
  const statuses = [
    "CONNECTING TO NEURAL SOC...",
    "BYPASSING FIREWALLS...",
    "DECRYPTING THREAT FEEDS...",
    "INITIALIZING AUTONOMOUS AGENTS...",
    "KAVACH GATE OPEN."
  ];

  // ===== HERO ENTRANCE SEQUENCE =====
  const heroTL = gsap.timeline({ paused: true, defaults: { ease: 'power3.out' } });
  heroTL
    .from('.nav-inner', { y: -70, opacity: 0, duration: 0.9, ease: 'back.out(1.4)' })
    .from('.hero-tags .tag', { opacity: 0, y: 20, stagger: 0.1, duration: 0.5 }, '-=0.3')
    .add(() => splitReveal('.hero-headline'), '-=0.2')
    .from('.hero-keywords', { opacity: 0, y: 15, duration: 0.6 }, '-=0.6')
    .from('.hero-description', { opacity: 0, y: 20, duration: 0.6 }, '-=0.5')
    .from('.hero-actions', { opacity: 0, y: 15, duration: 0.6 }, '-=0.4')
    .fromTo('.hero-video-container', { scale: 0.6, opacity: 0 },
      { scale: 1, opacity: 1, duration: 1.8, ease: 'power2.out' }, '-=1.2')
    .fromTo('.hero-dashboard-mockup', { y: 100, opacity: 0 },
      { y: 0, opacity: 1, duration: 1.2, ease: 'power3.out' }, '-=0.8')
    .fromTo('.three-container', { opacity: 0 },
      { opacity: 0.5, duration: 2 }, '-=1.5');

  if (loaderEl) {
    let progress = { val: 0 };
    gsap.to(progress, {
      val: 100,
      duration: 2.8,
      ease: 'power2.inOut',
      onUpdate: () => {
        if(pctEl) pctEl.innerText = progress.val.toFixed(2) + '%';
        if(barEl) barEl.style.width = progress.val + '%';
        
        const idx = Math.min(Math.floor((progress.val / 100) * statuses.length), statuses.length - 1);
        if(statusEl) statusEl.innerText = statuses[idx];
      },
      onComplete: () => {
        loaderEl.classList.add('gate-open');
        setTimeout(() => {
          heroTL.play();
        }, 400);
        setTimeout(() => loaderEl.style.display = 'none', 1000);
      }
    });
  } else {
    heroTL.play();
  }

  // ===== HERO PARALLAX ON SCROLL =====
  gsap.to('.hero-content-grid', {
    yPercent: 25, opacity: 0, ease: 'none',
    scrollTrigger: { trigger: '.hero-besync', start: 'top top', end: 'bottom top', scrub: 1.5 }
  });

  gsap.to('.hero-dashboard-mockup', {
    y: -50, ease: 'none',
    scrollTrigger: { trigger: '.hero-besync', start: '60% top', end: 'bottom top', scrub: 1.5 }
  });

  // ===== NARRATIVE SCROLLYTELLING =====
  const steps = gsap.utils.toArray('.story-step');
  steps.forEach((step, i) => {
    ScrollTrigger.create({
      trigger: step,
      start: 'top 60%',
      end: 'bottom 40%',
      toggleClass: 'is-active',
      onEnter: () => updateVisual(i, steps.length),
      onEnterBack: () => updateVisual(i, steps.length)
    });
  });

  function updateVisual(index, total) {
    const pct = ((index + 1) / total) * 100;
    gsap.to('.vis-bar', { width: `${pct}%`, duration: 0.5, ease: 'power2.out' });
    gsap.fromTo('.vis-hero-icon', 
      { scale: 0.8, opacity: 0.5 }, 
      { scale: 1, opacity: 1, duration: 0.4, ease: 'back.out(1.5)', overwrite: 'auto' }
    );
  }

  // ===== HORIZONTAL SCROLL GALLERY (Lando Style) =====
  const horizontalSection = document.querySelector('.horizontal-section');
  const horizontalTrack = document.querySelector('.horizontal-track');
  
  if (horizontalSection && horizontalTrack) {
    function getScrollAmount() {
      return -(horizontalTrack.scrollWidth - window.innerWidth + window.innerWidth * 0.15);
    }

    gsap.to(horizontalTrack, {
      x: getScrollAmount,
      ease: 'none',
      scrollTrigger: {
        trigger: horizontalSection,
        start: 'top top',
        end: () => `+=${getScrollAmount() * -1}`,
        pin: '.horizontal-sticky',
        scrub: 1,
        invalidateOnRefresh: true
      }
    });

    // Animate cards inside track on enter
    gsap.from('.horizontal-card', {
      y: 50, opacity: 0, stagger: 0.1, duration: 1, ease: 'power3.out',
      scrollTrigger: {
        trigger: horizontalSection, start: 'top 60%', once: true
      }
    });
  }

  // ===== COLOR PALETTE SHIFTS =====
  gsap.to('body', {
    backgroundColor: '#09090c',
    scrollTrigger: {
      trigger: '.command-section',
      start: 'top 80%',
      end: 'top 20%',
      scrub: true
    }
  });

  // ===== COMMAND CENTER GLASS CARDS =====
  ScrollTrigger.create({
    trigger: '.command-section', start: 'top 75%',
    onEnter: () => {
      gsap.fromTo('.command-grid .glass-card',
        { opacity: 0, y: 30, scale: 0.95 },
        { opacity: 1, y: 0, scale: 1, stagger: 0.06, duration: 0.6, ease: 'power3.out' }
      );
    }, once: true
  });

  // ===== FOOTER — Fade in =====
  gsap.fromTo('.footer-inner',
    { opacity: 0, y: 20 },
    {
      opacity: 1, y: 0, duration: 0.6,
      scrollTrigger: { trigger: '.footer-section', start: 'top 90%', once: true }
    }
  );

  // ===== DASHBOARD MOCKUP — Parallax tilt on scroll =====
  gsap.to('.hero-dashboard-mockup', {
    rotateX: -3, transformPerspective: 1000, ease: 'none',
    scrollTrigger: { trigger: '.hero-dashboard-mockup', start: 'top 80%', end: 'bottom 20%', scrub: 2 }
  });

  // ===== MAGNETIC INTERACTIVE LOGO & BUTTONS =====
  const magneticEls = document.querySelectorAll('.magnetic');
  magneticEls.forEach((el) => {
    el.addEventListener('mousemove', (e) => {
      const bound = el.getBoundingClientRect();
      const strength = el.dataset.strength || 15;
      const x = (((e.clientX - bound.left) / el.offsetWidth) - 0.5) * strength;
      const y = (((e.clientY - bound.top) / el.offsetHeight) - 0.5) * strength;
      
      gsap.to(el, {
        x: x,
        y: y,
        rotateX: -y,
        rotateY: x,
        scale: 1.05,
        ease: 'power3.out',
        duration: 0.4
      });
      
      if(el.classList.contains('nav-brand')) {
        gsap.to(el.querySelector('.brand-icon'), {
          rotateZ: x * 2,
          scale: 1.1,
          ease: 'power2.out',
          duration: 0.3
        });
      }
    });

    el.addEventListener('mouseleave', () => {
      gsap.to(el, { x: 0, y: 0, rotateX: 0, rotateY: 0, scale: 1, ease: 'elastic.out(1, 0.3)', duration: 1.2 });
      if(el.classList.contains('nav-brand')) {
        gsap.to(el.querySelector('.brand-icon'), { rotateZ: 0, scale: 1, ease: 'elastic.out(1, 0.3)', duration: 1.2 });
      }
    });
  });
}
