(function () {
  'use strict';

  const SVG_NS = 'http://www.w3.org/2000/svg';
  const SPRITE = '/assets/icons.svg';
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const $ = (id) => document.getElementById(id);

  function icon(name, extraClass) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', 'icon' + (extraClass ? ' ' + extraClass : ''));
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', `${SPRITE}#${name}`);
    svg.appendChild(use);
    return svg;
  }

  function hydrateIcons(root) {
    (root || document).querySelectorAll('i[data-icon]').forEach((el) => {
      el.replaceWith(icon(el.dataset.icon, el.className));
    });
  }

  function el(tag, opts, children) {
    const node = document.createElement(tag);
    if (opts) {
      for (const [k, v] of Object.entries(opts)) {
        if (v == null) continue;
        if (k === 'class') node.className = v;
        else if (k === 'text') node.textContent = v;
        else if (k === 'style') Object.assign(node.style, v);
        else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
        else node.setAttribute(k, v);
      }
    }
    (children || []).forEach((c) => c && node.append(c));
    return node;
  }

  function setButton(btn, iconName, label, spinning) {
    btn.replaceChildren();
    if (iconName) btn.append(icon(iconName, spinning ? 'spin' : ''));
    btn.append(document.createTextNode(label));
  }

  function showScreen(screenIds, activeId) {
    screenIds.forEach((id) => {
      const node = $(id);
      if (!node) return;
      const active = id === activeId;
      if (active && node.classList.contains('is-active')) return;
      node.classList.toggle('is-active', active);
      node.setAttribute('aria-hidden', active ? 'false' : 'true');
    });
  }

  let toastHost = null;
  function toast(message, type) {
    if (!toastHost) {
      toastHost = el('div', { class: 'toasts', role: 'status', 'aria-live': 'polite' });
      document.body.appendChild(toastHost);
    }
    const t = el('div', { class: 'toast ' + (type || '') }, [
      icon(type === 'error' ? 'alert' : type === 'ok' ? 'check' : 'sparkles'),
      el('span', { text: String(message) })
    ]);
    toastHost.appendChild(t);
    setTimeout(() => {
      t.classList.add('out');
      setTimeout(() => t.remove(), 320);
    }, 3200);
  }

  function setTimer(timerEl, remaining, total) {
    const value = timerEl.querySelector('.timer-value');
    value.textContent = Math.max(0, remaining);
    timerEl.style.setProperty('--p', total > 0 ? Math.max(0, remaining) / total : 0);
    timerEl.classList.toggle('urgent', remaining <= 5 && remaining > 0);
  }

  function countUp(node, to, duration) {
    const from = Number(node.dataset.value || 0);
    node.dataset.value = to;
    if (reducedMotion || from === to) {
      node.textContent = to.toLocaleString('tr-TR');
      return;
    }
    const d = duration || 900;
    const start = performance.now();
    const step = (now) => {
      const t = Math.min(1, (now - start) / d);
      const eased = 1 - Math.pow(1 - t, 3);
      node.textContent = Math.round(from + (to - from) * eased).toLocaleString('tr-TR');
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  function renderQr(container, text) {
    if (typeof window.qrcode !== 'function') return;
    const qr = window.qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    const n = qr.getModuleCount();
    let d = '';
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (qr.isDark(r, c)) d += `M${c} ${r}h1v1h-1z`;
      }
    }
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('viewBox', `0 0 ${n} ${n}`);
    svg.setAttribute('shape-rendering', 'crispEdges');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Katılım QR kodu');
    const path = document.createElementNS(SVG_NS, 'path');
    path.setAttribute('d', d);
    path.setAttribute('fill', '#07080a');
    svg.appendChild(path);
    container.replaceChildren(svg);
  }

  function confetti(options) {
    if (reducedMotion) return;
    const opts = Object.assign({ count: 160, duration: 4200 }, options);
    const canvas = el('canvas', { class: 'confetti', 'aria-hidden': 'true' });
    document.body.appendChild(canvas);
    const ctx = canvas.getContext('2d');
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const resize = () => {
      canvas.width = innerWidth * dpr;
      canvas.height = innerHeight * dpr;
    };
    resize();
    const colors = ['#5ce1e6', '#e8c37a', '#f7e2b0', '#f3f5f6', '#4c8dff', '#f0506e'];
    const parts = Array.from({ length: opts.count }, () => ({
      x: innerWidth * (0.2 + Math.random() * 0.6),
      y: innerHeight * 0.35 + Math.random() * 40,
      vx: (Math.random() - 0.5) * 14,
      vy: -8 - Math.random() * 12,
      w: 5 + Math.random() * 6,
      h: 8 + Math.random() * 10,
      rot: Math.random() * Math.PI,
      vr: (Math.random() - 0.5) * 0.3,
      color: colors[(Math.random() * colors.length) | 0]
    }));
    const start = performance.now();
    const frame = (now) => {
      const elapsed = now - start;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, innerWidth, innerHeight);
      const fade = Math.max(0, 1 - Math.max(0, elapsed - opts.duration * 0.6) / (opts.duration * 0.4));
      for (const p of parts) {
        p.vy += 0.32;
        p.vx *= 0.985;
        p.x += p.vx;
        p.y += p.vy;
        p.rot += p.vr;
        ctx.save();
        ctx.globalAlpha = fade;
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rot);
        ctx.fillStyle = p.color;
        ctx.fillRect(-p.w / 2, -p.h / 2, p.w, p.h * Math.abs(Math.cos(p.rot * 2)));
        ctx.restore();
      }
      if (elapsed < opts.duration) requestAnimationFrame(frame);
      else canvas.remove();
    };
    requestAnimationFrame(frame);
  }

  function vibrate(pattern) {
    if (navigator.vibrate) {
      try { navigator.vibrate(pattern); } catch (e) { /* unsupported */ }
    }
  }

  window.UI = { $, icon, hydrateIcons, el, setButton, showScreen, toast, setTimer, countUp, renderQr, confetti, vibrate, reducedMotion };
  document.addEventListener('DOMContentLoaded', () => hydrateIcons());
})();
