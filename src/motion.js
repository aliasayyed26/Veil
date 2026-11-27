(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.Veil = root.Veil || {};
    root.Veil.Motion = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const BLOCK_CHARS = '\u2591\u2592\u2593\u2588';
  const MAX_STAGGER_ITEMS = 200;
  const MAX_TOTAL_STAGGER_MS = 600;
  const DEFAULT_STEP_STAGGER_MS = 25;

  const elementCancels = typeof WeakMap !== 'undefined' ? new WeakMap() : null;
  const activeJobs = new Set();

  let mediaQuery = null;
  let userPreference = null; // null = follow OS, boolean = explicit in-memory override

  function getMediaQuery() {
    if (mediaQuery) return mediaQuery;
    if (typeof window !== 'undefined' && typeof window.matchMedia === 'function') {
      mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    }
    return mediaQuery;
  }

  function osPrefersReduced() {
    const mq = getMediaQuery();
    return Boolean(mq && mq.matches);
  }

  /**
   * Returns true when reduced motion is active (via OS setting or in-memory toggle).
   */
  function prefersReducedMotion() {
    if (userPreference !== null) {
      return !userPreference;
    }
    return osPrefersReduced();
  }

  function syncMotionAttribute() {
    if (typeof document === 'undefined' || !document.documentElement) return;
    document.documentElement.setAttribute('data-motion', prefersReducedMotion() ? 'reduced' : 'full');
  }

  function setUserMotionPreference(enabled) {
    userPreference = Boolean(enabled);
    if (!userPreference) {
      cancelAll();
    }
    syncMotionAttribute();
    return userPreference;
  }

  function isMotionEnabled() {
    return !prefersReducedMotion();
  }

  function registerJob(el, cancelFn) {
    cancelForElement(el);
    const wrapped = function () {
      activeJobs.delete(wrapped);
      if (elementCancels && el && elementCancels.get(el) === wrapped) {
        elementCancels.delete(el);
      }
      cancelFn();
    };
    activeJobs.add(wrapped);
    if (elementCancels && el) {
      elementCancels.set(el, wrapped);
    }
    return wrapped;
  }

  function cancelForElement(el) {
    if (!elementCancels || !el) return;
    const prev = elementCancels.get(el);
    if (prev) {
      prev();
    }
  }

  function cancelAll() {
    const jobs = Array.from(activeJobs);
    for (let i = 0; i < jobs.length; i++) {
      jobs[i]();
    }
  }

  function easeOutCubic(t) {
    return 1 - Math.pow(1 - t, 3);
  }

  /**
   * Smoothly animates a numeric counter from `from` to `to` over ~400 ms using rAF.
   */
  function animateCounter(el, from, to, options) {
    if (!el) return Promise.resolve();
    const startVal = Number.isFinite(from) ? from : 0;
    const endVal = Number.isFinite(to) ? to : 0;
    const opts = options || {};
    const duration = typeof opts.duration === 'number' ? opts.duration : 400;

    cancelForElement(el);

    if (prefersReducedMotion() || startVal === endVal || typeof requestAnimationFrame !== 'function') {
      el.textContent = String(endVal);
      return Promise.resolve();
    }

    return new Promise(function (resolve) {
      let rafId = 0;
      let startTime = 0;
      let done = false;

      const cancelFn = registerJob(el, function () {
        if (done) return;
        done = true;
        if (rafId) cancelAnimationFrame(rafId);
        el.textContent = String(endVal);
        resolve();
      });

      function tick(now) {
        if (done) return;
        if (!startTime) startTime = now;
        const elapsed = now - startTime;
        const progress = Math.min(1, elapsed / duration);
        const eased = easeOutCubic(progress);
        const current = Math.round(startVal + (endVal - startVal) * eased);
        el.textContent = String(current);

        if (progress < 1) {
          rafId = requestAnimationFrame(tick);
        } else {
          done = true;
          activeJobs.delete(cancelFn);
          if (elementCancels && elementCancels.get(el) === cancelFn) {
            elementCancels.delete(el);
          }
          el.textContent = String(endVal);
          resolve();
        }
      }

      rafId = requestAnimationFrame(tick);
    });
  }

  /**
   * Runs a GPU-accelerated vertical scan line sweep across a diff panel (~800 ms).
   */
  function runScanSweep(panel, options) {
    if (!panel) return Promise.resolve({ cancelled: false });
    const opts = options || {};
    const duration = typeof opts.duration === 'number' ? opts.duration : 800;
    const line = panel.querySelector('.scan-line');

    cancelForElement(panel);

    if (prefersReducedMotion() || !line || typeof line.animate !== 'function') {
      if (line) {
        line.style.opacity = '0';
      }
      return Promise.resolve({ cancelled: false });
    }

    const travelY = Math.max(180, panel.clientHeight || 240);

    return new Promise(function (resolve) {
      let cancelled = false;
      const anim = line.animate(
        [
          { transform: 'translate3d(0, -12px, 0)', opacity: 0 },
          { transform: 'translate3d(0, ' + Math.round(travelY * 0.1) + 'px, 0)', opacity: 1, offset: 0.1 },
          { transform: 'translate3d(0, ' + Math.round(travelY * 0.9) + 'px, 0)', opacity: 0.95, offset: 0.9 },
          { transform: 'translate3d(0, ' + (travelY + 12) + 'px, 0)', opacity: 0 }
        ],
        {
          duration: duration,
          easing: 'cubic-bezier(0.22, 1, 0.36, 1)',
          fill: 'none'
        }
      );

      const cancelFn = registerJob(panel, function () {
        if (cancelled) return;
        cancelled = true;
        try {
          anim.cancel();
        } catch (_err) {
          // Ignore animation cancel errors on detached nodes
        }
        line.style.opacity = '0';
        resolve({ cancelled: true });
      });

      anim.onfinish = function () {
        activeJobs.delete(cancelFn);
        if (elementCancels && elementCancels.get(panel) === cancelFn) {
          elementCancels.delete(panel);
        }
        line.style.opacity = '0';
        resolve({ cancelled: cancelled });
      };
      anim.oncancel = function () {
        activeJobs.delete(cancelFn);
        resolve({ cancelled: true });
      };
    });
  }

  /**
   * Staggers highlight entrance (opacity + scale) inside a diff panel.
   * Caps at 200 items and 600 ms total stagger; falls back to a panel fade for large inputs.
   */
  function revealHighlights(panel, options) {
    if (!panel) return Promise.resolve();
    const opts = options || {};
    const tokens = panel.querySelectorAll('.pii-token');
    const count = tokens.length;

    if (count === 0) return Promise.resolve();

    if (prefersReducedMotion() || typeof Element.prototype.animate !== 'function') {
      return Promise.resolve();
    }

    if (count > MAX_STAGGER_ITEMS) {
      const surface = panel.querySelector('.diff-surface') || panel;
      const fade = surface.animate(
        [{ opacity: 0.65 }, { opacity: 1 }],
        { duration: 180, easing: 'cubic-bezier(0.22, 1, 0.36, 1)' }
      );
      return fade.finished.catch(function () {});
    }

    const stepDelay = Math.min(DEFAULT_STEP_STAGGER_MS, Math.floor(MAX_TOTAL_STAGGER_MS / count));
    const animations = [];
    const baseDelay = typeof opts.baseDelay === 'number' ? opts.baseDelay : 0;

    for (let i = 0; i < count; i++) {
      const el = tokens[i];
      const delay = baseDelay + Math.min(MAX_TOTAL_STAGGER_MS, i * stepDelay);
      const anim = el.animate(
        [
          { opacity: 0, transform: 'scale(0.96)' },
          { opacity: 1, transform: 'scale(1)' }
        ],
        {
          duration: 220,
          delay: delay,
          easing: 'cubic-bezier(0.22, 1, 0.36, 1)',
          fill: 'backwards'
        }
      );
      animations.push(anim);
    }

    const cancelFn = registerJob(tokens[0], function () {
      for (let j = 0; j < animations.length; j++) {
        try {
          animations[j].cancel();
        } catch (_err) {
          // Ignore
        }
      }
    });

    const last = animations[animations.length - 1];
    return last.finished
      .catch(function () {})
      .then(function () {
        activeJobs.delete(cancelFn);
      });
  }

  /**
   * Cosmetic block-character scramble that resolves to the exact `finalText` within ~300 ms.
   * Never alters underlying sanitized data; skips under reduced motion or large token counts.
   */
  function scrambleResolve(el, finalText, options) {
    if (!el) return Promise.resolve();
    const target = typeof finalText === 'string' ? finalText : String(finalText || '');
    const opts = options || {};
    const duration = typeof opts.duration === 'number' ? opts.duration : 300;
    const delay = typeof opts.delay === 'number' ? opts.delay : 0;

    cancelForElement(el);

    if (prefersReducedMotion() || !target || typeof requestAnimationFrame !== 'function') {
      el.textContent = target;
      return Promise.resolve();
    }

    return new Promise(function (resolve) {
      let rafId = 0;
      let startTime = 0;
      let done = false;

      const cancelFn = registerJob(el, function () {
        if (done) return;
        done = true;
        if (rafId) cancelAnimationFrame(rafId);
        el.textContent = target;
        resolve();
      });

      function tick(now) {
        if (done) return;
        if (!startTime) startTime = now;
        const elapsed = now - startTime - delay;

        if (elapsed < 0) {
          rafId = requestAnimationFrame(tick);
          return;
        }

        const progress = Math.min(1, elapsed / duration);
        if (progress >= 1) {
          done = true;
          activeJobs.delete(cancelFn);
          if (elementCancels && elementCancels.get(el) === cancelFn) {
            elementCancels.delete(el);
          }
          el.textContent = target;
          resolve();
          return;
        }

        const locked = Math.floor(progress * target.length);
        let out = target.slice(0, locked);
        for (let i = locked; i < target.length; i++) {
          const ch = target.charAt(i);
          if (ch === ' ' || ch === '-' || ch === '.' || ch === '@') {
            out += ch;
          } else {
            const idx = (i + Math.floor(elapsed / 38)) % BLOCK_CHARS.length;
            out += BLOCK_CHARS.charAt(idx);
          }
        }
        el.textContent = out;
        rafId = requestAnimationFrame(tick);
      }

      rafId = requestAnimationFrame(tick);
    });
  }

  /**
   * Pauses looping CSS animations when the document is hidden or observed elements are off-screen.
   */
  function initVisibilityController(observedElements) {
    if (typeof document === 'undefined') return function () {};

    let isTabHidden = Boolean(document.hidden);
    let anyVisible = true;
    const visibilityMap = new Map();

    function updatePausedState() {
      const shouldPause = isTabHidden || !anyVisible;
      document.documentElement.classList.toggle('motion-paused', shouldPause);
    }

    function onVisibilityChange() {
      isTabHidden = Boolean(document.hidden);
      updatePausedState();
    }

    document.addEventListener('visibilitychange', onVisibilityChange);

    let observer = null;
    if (typeof IntersectionObserver === 'function' && Array.isArray(observedElements) && observedElements.length > 0) {
      observer = new IntersectionObserver(function (entries) {
        for (let i = 0; i < entries.length; i++) {
          visibilityMap.set(entries[i].target, entries[i].isIntersecting);
        }
        anyVisible = false;
        visibilityMap.forEach(function (visible) {
          if (visible) anyVisible = true;
        });
        updatePausedState();
      }, { threshold: 0.02 });

      for (let i = 0; i < observedElements.length; i++) {
        if (observedElements[i]) {
          visibilityMap.set(observedElements[i], true);
          observer.observe(observedElements[i]);
        }
      }
    }

    const mq = getMediaQuery();
    function onMediaChange() {
      if (userPreference === null) {
        if (osPrefersReduced()) {
          cancelAll();
        }
        syncMotionAttribute();
      }
    }
    if (mq && typeof mq.addEventListener === 'function') {
      mq.addEventListener('change', onMediaChange);
    }

    syncMotionAttribute();
    updatePausedState();

    return function cleanup() {
      document.removeEventListener('visibilitychange', onVisibilityChange);
      if (observer) observer.disconnect();
      if (mq && typeof mq.removeEventListener === 'function') {
        mq.removeEventListener('change', onMediaChange);
      }
    };
  }

  return {
    MAX_STAGGER_ITEMS: MAX_STAGGER_ITEMS,
    prefersReducedMotion: prefersReducedMotion,
    isMotionEnabled: isMotionEnabled,
    setUserMotionPreference: setUserMotionPreference,
    syncMotionAttribute: syncMotionAttribute,
    animateCounter: animateCounter,
    runScanSweep: runScanSweep,
    revealHighlights: revealHighlights,
    scrambleResolve: scrambleResolve,
    cancelForElement: cancelForElement,
    cancelAll: cancelAll,
    initVisibilityController: initVisibilityController
  };
});
