// Minimal canvas confetti — no dependencies. ~50 lines.
(function () {
  function readAccent(n) {
    var v = getComputedStyle(document.documentElement).getPropertyValue('--accent-' + n).trim();
    return v || ['#22d3ee', '#a855f7', '#ec4899'][n - 1];
  }
  function rand(min, max) { return Math.random() * (max - min) + min; }

  window.confetti = function (opts) {
    opts = opts || {};
    if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    var count = opts.count || 120;
    var colors = opts.colors || [readAccent(1), readAccent(2), readAccent(3), '#fff'];
    var canvas = document.createElement('canvas');
    canvas.style.position = 'fixed';
    canvas.style.inset = '0';
    canvas.style.pointerEvents = 'none';
    canvas.style.zIndex = '9999';
    canvas.width = innerWidth;
    canvas.height = innerHeight;
    document.body.appendChild(canvas);
    var ctx = canvas.getContext('2d');
    var particles = [];
    for (var i = 0; i < count; i++) {
      particles.push({
        x: innerWidth / 2 + rand(-40, 40),
        y: innerHeight / 2 + rand(-20, 20),
        vx: rand(-6, 6),
        vy: rand(-14, -4),
        size: rand(5, 10),
        color: colors[(Math.random() * colors.length) | 0],
        rot: rand(0, Math.PI * 2),
        vr: rand(-0.3, 0.3),
        life: rand(70, 120),
      });
    }
    var frames = 0;
    function tick() {
      frames++;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      var alive = 0;
      for (var i = 0; i < particles.length; i++) {
        var p = particles[i];
        if (p.life <= 0) continue;
        p.life--;
        p.vy += 0.35; // gravity
        p.vx *= 0.99;
        p.x += p.vx;
        p.y += p.vy;
        p.rot += p.vr;
        ctx.save();
        ctx.translate(p.x, p.y);
        ctx.rotate(p.rot);
        ctx.fillStyle = p.color;
        ctx.globalAlpha = Math.max(0, Math.min(1, p.life / 60));
        ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size * 0.6);
        ctx.restore();
        alive++;
      }
      if (alive > 0 && frames < 240) {
        requestAnimationFrame(tick);
      } else {
        canvas.remove();
      }
    }
    requestAnimationFrame(tick);
  };
})();
