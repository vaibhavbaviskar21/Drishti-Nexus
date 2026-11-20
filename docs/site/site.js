// The hero field: the demo's own auth.log lines on the theme's 8 by 16 cell, sparse under the headline, dense toward the dashboard.
(() => {
  const canvas = document.querySelector('[data-field]');
  if (!canvas) return;
  const LINES = [
    'web01 sshd[2001]: Accepted publickey for alice from 10.0.0.5 port 50100 ssh2',
    'web01 sshd[2101]: Failed password for deploy from 203.0.113.50 port 51120 ssh2',
    'web01 sshd[2103]: Failed password for deploy from 203.0.113.50 port 51124 ssh2',
    'web01 sshd[2105]: Failed password for deploy from 203.0.113.50 port 51128 ssh2',
    'web01 sshd[2107]: Accepted password for deploy from 203.0.113.50 port 51132 ssh2',
    'db01 sshd[3107]: Accepted password for deploy from 10.0.0.11 port 40222 ssh2',
    'web01 sshd[2001]: pam_unix(sshd:session): session closed for user alice',
  ];
  const css = getComputedStyle(document.documentElement);
  const tint = ['--color-glyph-1', '--color-glyph-2', '--color-glyph-3', '--color-glyph-4'].map((v) => css.getPropertyValue(v).trim());
  const font = css.getPropertyValue('--font-outlier').trim();
  const W = 8, H = 16;
  const rand = (a, b) => { const x = Math.sin(a * 127.1 + b * 311.7) * 43758.5453; return x - Math.floor(x); };
  const smooth = (e0, e1, x) => { const t = Math.min(1, Math.max(0, (x - e0) / (e1 - e0))); return t * t * (3 - 2 * t); };
  const draw = () => {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight;
    canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    ctx.font = `12px ${font}`;
    ctx.textBaseline = 'top';
    const cols = Math.ceil(w / W), rows = Math.ceil(h / H);
    for (let r = 0; r < rows; r++) {
      const line = LINES[r % LINES.length];
      const hostile = line.includes('deploy');
      for (let c = 0; c < cols; c++) {
        const ch = line[(c + r * 13) % line.length];
        if (ch === ' ') continue;
        const fx = c / cols;
        const density = 0.05 + 0.5 * smooth(0.36, 0.64, fx);
        const n = rand(r, c);
        if (n > density) continue;
        let i = fx < 0.5 ? 0 : n < density * 0.5 ? 1 : 0;
        if (hostile && fx > 0.5) i = n < density * 0.4 ? 3 : 2;
        ctx.fillStyle = tint[i];
        ctx.fillText(ch, c * W, r * H + 2);
      }
    }
  };
  draw();
  let t;
  new ResizeObserver(() => { clearTimeout(t); t = setTimeout(draw, 120); }).observe(canvas);
})();

// The bar retracts on the way down and returns on the way up.
(() => {
  const bar = document.querySelector('[data-bar]');
  if (!bar) return;
  let last = scrollY, ticking = false;
  addEventListener('scroll', () => {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      const y = scrollY;
      bar.classList.toggle('is-hidden', y > last && y > 400);
      last = y; ticking = false;
    });
  }, { passive: true });
})();

// Copy the build commands.
document.querySelectorAll('[data-copy]').forEach((btn) => {
  const src = document.getElementById(btn.dataset.copy);
  const status = document.querySelector('[data-copy-status]');
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(src.textContent);
      btn.textContent = 'Copied';
    } catch {
      getSelection().selectAllChildren(src);
      btn.textContent = 'Selected';
      if (status) status.textContent = 'The clipboard is blocked here; the commands are selected, press Ctrl+C.';
    }
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  });
});
