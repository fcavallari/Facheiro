// Facheiro site: the few things the pages do. Every part checks that its
// element exists, so the home pages and the references share this file.
// Without this script every page still reads in full: the terminal output
// and the findings are in the HTML, and the menu links stay visible.
(function () {
  "use strict";

  var pt = document.documentElement.lang === "pt-BR";
  var L = pt
    ? { copied: "Copiado", failed: "Não foi possível copiar", skip: "Pular animação", replay: "Rodar de novo", menu: "Menu", close: "Fechar", none: "Nenhum achado com esta gravidade." }
    : { copied: "Copied", failed: "Copy failed", skip: "Skip animation", replay: "Run again", menu: "Menu", close: "Close", none: "No findings with this severity." };

  var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  //////////////
  // Copy buttons: <button command="--copy" commandfor="<pre id>">. The
  // bubble after each button is its live region; the button keeps its
  // name and stays enabled, so a failed copy can be retried.
  //////////////
  var copyTimers = new WeakMap();
  var lastMessage = "";

  function report(button, ok) {
    var tip = button.nextElementSibling;
    clearTimeout(copyTimers.get(button));
    button.removeAttribute("data-copied");
    button.removeAttribute("data-failed");
    var message = ok ? L.copied : L.failed;
    // VoiceOver skips a message identical to the last one
    if (message === lastMessage) message += " ";
    lastMessage = message;
    tip.textContent = "";
    void button.offsetWidth;
    button.setAttribute(ok ? "data-copied" : "data-failed", "");
    requestAnimationFrame(function () { tip.textContent = message; });
    copyTimers.set(button, setTimeout(function () {
      button.removeAttribute("data-copied");
      button.removeAttribute("data-failed");
      tip.textContent = "";
    }, 2000));
  }

  function copy(button, target) {
    // innerText keeps the line breaks; the "$ " prompts are not part of the command
    var text = target.innerText.replace(/^\$ /gm, "").trim();
    if (!text) return;
    try {
      navigator.clipboard.writeText(text).then(function () { report(button, true); }, function () { report(button, false); });
    } catch (e) {
      report(button, false);
    }
  }

  // command events do not bubble: listen in the capture phase
  document.addEventListener("command", function (event) {
    if (event.command === "--copy") copy(event.source, event.target);
  }, true);

  // Browsers without Invoker Commands: the same copy() from a click
  if (!("CommandEvent" in window)) {
    document.addEventListener("click", function (event) {
      var button = event.target.closest ? event.target.closest('button[command="--copy"]') : null;
      if (!button) return;
      var target = document.getElementById(button.getAttribute("commandfor"));
      if (target) copy(button, target);
    });
  }

  //////////////
  // Header: the menu on narrow screens, and a tone step once scrolled
  //////////////
  var head = document.querySelector(".site-head");
  var toggle = document.querySelector(".menu-toggle");
  var links = document.getElementById("nav-links");

  if (toggle && links) {
    // only now hide the links behind the button: without this script they stay listed
    document.documentElement.classList.add("menu-ready");
    var setOpen = function (open) {
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
      toggle.textContent = open ? L.close : L.menu;
      if (open) links.setAttribute("data-open", ""); else links.removeAttribute("data-open");
    };
    toggle.addEventListener("click", function () {
      setOpen(toggle.getAttribute("aria-expanded") !== "true");
    });
    links.addEventListener("click", function (event) {
      if (event.target.closest("a")) setOpen(false);
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape" && toggle.getAttribute("aria-expanded") === "true") {
        setOpen(false);
        toggle.focus();
      }
    });
  }

  if (head) {
    var onScroll = function () {
      if (window.scrollY > 8) head.setAttribute("data-scrolled", ""); else head.removeAttribute("data-scrolled");
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    onScroll();
  }

  //////////////
  // Entrances: each section's parts rise once as it comes into view
  //////////////
  var reveals = document.querySelectorAll("[data-reveal]");
  if (reveals.length) {
    if (reduceMotion || !("IntersectionObserver" in window)) {
      reveals.forEach(function (el) { el.classList.add("is-in"); });
    } else {
      // hidden only once the observer that shows them again exists
      document.documentElement.classList.add("reveal-on");
      var revealer = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-in");
          revealer.unobserve(entry.target);
        });
      }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
      reveals.forEach(function (el) { revealer.observe(el); });
    }
  }

  //////////////
  // The findings filters on the admin fragment work like the plugin's
  //////////////
  document.querySelectorAll("[data-filters]").forEach(function (bar) {
    var table = document.getElementById(bar.getAttribute("data-filters"));
    if (!table) return;
    var rows = table.querySelectorAll("tbody tr[data-sev]");
    var empty = table.querySelector(".wp-empty-row");
    bar.addEventListener("click", function (event) {
      var button = event.target.closest("button[data-sev]");
      if (!button) return;
      var sev = button.getAttribute("data-sev");
      bar.querySelectorAll("button[data-sev]").forEach(function (b) {
        b.setAttribute("aria-pressed", b === button ? "true" : "false");
      });
      var shown = 0;
      rows.forEach(function (row) {
        var show = sev === "all" || row.getAttribute("data-sev") === sev;
        row.hidden = !show;
        if (show) shown++;
      });
      if (empty) empty.hidden = shown > 0;
    });
  });

  //////////////
  // The facheiro: a fire climbs the cactus and burns the thorns off,
  // the way it is prepared in the dry season. What is left is clean.
  //////////////
  var canvas = document.getElementById("cacto");
  if (canvas && canvas.getContext) burnCactus(canvas);

  function burnCactus(canvas) {
    var ctx = canvas.getContext("2d");
    var INK = "#14302d", STEM = "#4f8f88", RIB = "#2b6a64", THORN = "#c1911f";
    var EMBER = "#e2551d", SUN = "#ecdca8", GROUND_Y = 1;
    var BURN_MS = 3400;
    var W = 0, H = 0, stems = [], thorns = [], embers = [];
    var startTime = 0, running = false, visible = true;

    // trunk and arms in units of the canvas: x, top, bottom, width
    var PLAN = [
      { x: 0.50, top: 0.10, bottom: GROUND_Y, w: 0.105 },
      { x: 0.24, top: 0.36, bottom: 0.70, w: 0.085, joinX: 0.50 },
      { x: 0.77, top: 0.24, bottom: 0.56, w: 0.085, joinX: 0.50 },
      { x: 0.90, top: 0.54, bottom: 0.80, w: 0.07, joinX: 0.50 }
    ];

    // deterministic scatter, so the thorns sit in the same place on every run
    var seed = 7;
    function rnd() {
      seed = (seed * 16807) % 2147483647;
      return (seed - 1) / 2147483646;
    }

    function build() {
      var rect = canvas.getBoundingClientRect();
      W = Math.max(200, Math.round(rect.width));
      H = Math.max(200, Math.round(rect.height));
      var dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(W * dpr);
      canvas.height = Math.round(H * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

      seed = 7;
      stems = PLAN.map(function (p) {
        return {
          x: p.x * W, top: p.top * H, bottom: p.bottom * H, w: p.w * W,
          joinX: p.joinX === undefined ? null : p.joinX * W
        };
      });

      thorns = [];
      var step = Math.max(11, H / 34);
      stems.forEach(function (s) {
        [-0.5, -0.17, 0.17, 0.5].forEach(function (lane, li) {
          var edge = Math.abs(lane) === 0.5;
          for (var y = s.top + s.w * 0.35 + (li % 2) * step * 0.5; y < s.bottom - 4; y += step) {
            thorns.push({
              x: s.x + lane * s.w,
              y: y + (rnd() - 0.5) * 3,
              dir: lane < 0 ? -1 : 1,
              edge: edge,
              len: (edge ? 0.085 : 0.05) * s.w * 2 * (0.8 + rnd() * 0.5),
              spark: false
            });
          }
        });
      });
      embers = [];
    }

    function stemPath(s) {
      ctx.beginPath();
      if (null !== s.joinX) {
        // the arm leaves the trunk sideways and turns up
        var r = Math.min(Math.abs(s.x - s.joinX), s.w * 0.9);
        var dir = s.x < s.joinX ? 1 : -1;
        ctx.moveTo(s.joinX, s.bottom);
        ctx.lineTo(s.x + dir * r, s.bottom);
        ctx.quadraticCurveTo(s.x, s.bottom, s.x, s.bottom - r);
      } else {
        ctx.moveTo(s.x, s.bottom);
      }
      ctx.lineTo(s.x, s.top + s.w / 2);
    }

    function drawStems() {
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      // arms first, so the trunk overlaps their joints
      [1, 2, 3, 0].forEach(function (i) {
        var s = stems[i];
        stemPath(s);
        ctx.strokeStyle = INK;
        ctx.lineWidth = s.w + 6;
        ctx.stroke();
        stemPath(s);
        ctx.strokeStyle = STEM;
        ctx.lineWidth = s.w;
        ctx.stroke();
        ctx.strokeStyle = RIB;
        ctx.lineWidth = Math.max(1.5, s.w * 0.045);
        [-0.17, 0.17].forEach(function (lane) {
          ctx.beginPath();
          ctx.moveTo(s.x + lane * s.w, s.top + s.w * 0.3);
          ctx.lineTo(s.x + lane * s.w, s.bottom - (null === s.joinX ? 0 : s.w * 0.7));
          ctx.stroke();
        });
      });
    }

    function drawScene(fireY, now) {
      ctx.clearRect(0, 0, W, H);

      ctx.fillStyle = SUN;
      ctx.beginPath();
      ctx.arc(W * 0.74, H * 0.2, W * 0.2, 0, Math.PI * 2);
      ctx.fill();

      drawStems();

      // the trunk stands on the page's horizon bar, drawn right under the canvas

      // thorns the fire has not reached
      ctx.strokeStyle = THORN;
      ctx.lineWidth = Math.max(1.3, W / 320);
      for (var i = 0; i < thorns.length; i++) {
        var t = thorns[i];
        if (t.y >= fireY) {
          if (!t.spark) {
            t.spark = true;
            if (now && (t.edge || i % 3 === 0)) {
              embers.push({ x: t.x, y: t.y, vx: (rnd() - 0.5) * 0.03, vy: -(0.03 + rnd() * 0.05), born: now, life: 700 + rnd() * 900 });
            }
          }
          continue;
        }
        ctx.beginPath();
        if (t.edge) {
          ctx.moveTo(t.x, t.y);
          ctx.lineTo(t.x + t.dir * t.len, t.y - t.len * 0.5);
          ctx.moveTo(t.x, t.y);
          ctx.lineTo(t.x + t.dir * t.len, t.y + t.len * 0.35);
        } else {
          ctx.moveTo(t.x - t.len, t.y - t.len * 0.6);
          ctx.lineTo(t.x + t.len, t.y + t.len * 0.6);
          ctx.moveTo(t.x + t.len, t.y - t.len * 0.6);
          ctx.lineTo(t.x - t.len, t.y + t.len * 0.6);
        }
        ctx.stroke();
      }

      // the fire line: small flames where it meets each stem
      if (fireY > 0 && fireY < GROUND_Y * H) {
        ctx.fillStyle = EMBER;
        stems.forEach(function (s) {
          if (fireY < s.top || fireY > s.bottom) return;
          for (var k = -1; k <= 1; k++) {
            var fx = s.x + k * s.w * 0.36;
            var fh = s.w * (0.34 + 0.14 * Math.sin((now || 0) / 90 + k * 2 + s.x));
            ctx.beginPath();
            ctx.moveTo(fx - s.w * 0.17, fireY + 2);
            ctx.quadraticCurveTo(fx - s.w * 0.05, fireY - fh * 0.4, fx, fireY - fh);
            ctx.quadraticCurveTo(fx + s.w * 0.05, fireY - fh * 0.4, fx + s.w * 0.17, fireY + 2);
            ctx.closePath();
            ctx.fill();
          }
        });
      }

      var live = [];
      for (var j = 0; j < embers.length; j++) {
        var e = embers[j], age = now - e.born;
        if (age > e.life) continue;
        live.push(e);
        ctx.globalAlpha = 1 - age / e.life;
        ctx.fillStyle = EMBER;
        ctx.fillRect(e.x + e.vx * age, e.y + e.vy * age, 3, 3);
      }
      ctx.globalAlpha = 1;
      embers = live;
    }

    function frame(now) {
      if (!visible) { running = false; return; }
      var p = Math.min(1, (now - startTime) / BURN_MS);
      var fireY = GROUND_Y * H - p * (GROUND_Y * H - H * 0.04);
      drawScene(p >= 1 ? -1 : fireY, now);
      if (p < 1 || embers.length) {
        requestAnimationFrame(frame);
      } else {
        running = false;
      }
    }

    function burn() {
      build();
      if (reduceMotion) {
        // still picture: the lower half already burnt clean
        thorns.forEach(function (t) { t.spark = true; });
        drawScene(H * 0.5, 0);
        return;
      }
      startTime = performance.now() + 500;
      drawScene(H * 2, 0);
      if (!running) {
        running = true;
        requestAnimationFrame(frame);
      }
    }

    var resizeTimer = null;
    window.addEventListener("resize", function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(function () {
        build();
        if (reduceMotion) {
          drawScene(H * 0.5, 0);
        } else if (!running) {
          thorns.forEach(function (t) { t.spark = true; });
          drawScene(-1, 0);
        }
      }, 150);
    });

    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (entries) {
        var was = visible;
        visible = entries[0].isIntersecting;
        if (visible && !was && !reduceMotion && !running && performance.now() - startTime < BURN_MS) {
          running = true;
          requestAnimationFrame(frame);
        }
      }).observe(canvas);
    }

    var again = document.getElementById("reburn");
    if (again) again.addEventListener("click", burn);
    burn();
  }

  //////////////
  // The terminal: the HTML already holds the whole run; once it scrolls
  // into view the script types it out again, line by line.
  //////////////
  var term = document.getElementById("term");
  var replay = document.getElementById("replay");
  if (term && replay) typeTerminal(term, replay);

  function typeTerminal(term, replay) {
    // read the run back from the markup, so the HTML is the one source
    var LINES = [];
    var current = null;
    Array.prototype.forEach.call(term.childNodes, function (node) {
      if (node.nodeType === 3) {
        var parts = node.nodeValue.split("\n");
        if (current && parts[0]) current.push({ cls: "", text: parts[0] });
        for (var i = 1; i < parts.length; i++) {
          if (current) LINES.push(current);
          current = [];
          if (parts[i]) current.push({ cls: "", text: parts[i] });
        }
      } else {
        if (!current) current = [];
        current.push({ cls: node.className, text: node.textContent });
      }
    });
    if (current && current.length) LINES.push(current);
    var timers = [];

    function clearTerm() {
      timers.forEach(clearTimeout);
      timers = [];
      while (term.firstChild) term.removeChild(term.firstChild);
    }

    function span(cls, text) {
      var s = document.createElement("span");
      if (cls) s.className = cls;
      s.textContent = text;
      return s;
    }

    function isCommand(line) { return line.length > 1 && line[0].cls === "ctx" && line[0].text === "$ "; }

    function appendLine(line) {
      line.forEach(function (part) { term.appendChild(span(part.cls, part.text)); });
      term.appendChild(document.createTextNode("\n"));
    }

    function showAll() {
      clearTerm();
      LINES.forEach(appendLine);
    }

    var playing = false;
    function settle() {
      playing = false;
      replay.textContent = L.replay;
    }

    function play() {
      showAll();
      term.style.minHeight = term.offsetHeight + "px";
      clearTerm();
      playing = true;
      replay.textContent = L.skip;
      var at = 200;
      var cursor = span("cursor", "");
      LINES.forEach(function (line, index) {
        var last = index === LINES.length - 1;
        if (isCommand(line)) {
          var cmd = line.slice(1).map(function (p) { return p.text; }).join("");
          var target = null;
          timers.push(setTimeout(function () {
            term.appendChild(span("ctx", "$ "));
            target = span("c", "");
            term.appendChild(target);
            term.appendChild(cursor);
          }, at));
          for (var i = 1; i <= cmd.length; i++) {
            (function (n) {
              timers.push(setTimeout(function () { target.textContent = cmd.slice(0, n); }, at + n * 22));
            })(i);
          }
          at += cmd.length * 22 + 380;
          timers.push(setTimeout(function () {
            if (cursor.parentNode) cursor.parentNode.removeChild(cursor);
            term.appendChild(document.createTextNode("\n"));
          }, at));
          at += cmd.length < 10 ? 120 : 900;
        } else if (last && line.length === 1 && line[0].text === "$ ") {
          timers.push(setTimeout(function () {
            term.appendChild(span("ctx", "$ "));
            term.appendChild(cursor);
          }, at));
        } else {
          timers.push(setTimeout(function () { appendLine(line); }, at));
          at += 140 + Math.random() * 110;
        }
      });
      timers.push(setTimeout(settle, at + 200));
    }

    replay.hidden = false;
    replay.addEventListener("click", function () {
      if (reduceMotion || playing) {
        showAll();
        settle();
      } else {
        play();
      }
    });

    // on a phone the run wraps to several screens: show it typed, no void
    var wide = !window.matchMedia || window.matchMedia("(min-width: 48em)").matches;
    if (!reduceMotion && wide && "IntersectionObserver" in window) {
      var played = false;
      new IntersectionObserver(function (entries, obs) {
        if (entries[0].isIntersecting && !played) {
          played = true;
          obs.disconnect();
          play();
        }
      }, { threshold: 0.35 }).observe(term);
    }
  }

  //////////////
  // Reference pages: mark the section in view in the table of contents.
  // CSS does it where scroll-target-group is supported; aria-current
  // mirrors it for assistive technology, and an IntersectionObserver
  // stands in elsewhere.
  //////////////
  var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".toc a"));
  if (tocLinks.length) {
    if (window.CSS && CSS.supports && CSS.supports("scroll-target-group: auto")) {
      var apply = function () {
        var cur = document.querySelector(".toc a:target-current");
        tocLinks.forEach(function (link) { link.setAttribute("aria-current", link === cur ? "true" : "false"); });
      };
      // :target-current is updated with the next rendering, after scrollend fires
      var sync = function () { requestAnimationFrame(function () { requestAnimationFrame(apply); }); };
      sync();
      document.addEventListener("scrollend", sync);
    } else if ("IntersectionObserver" in window) {
      var tocObserver = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
          if (!entry.isIntersecting) return;
          tocLinks.forEach(function (link) {
            var active = link.getAttribute("href") === "#" + entry.target.id;
            link.classList.toggle("target-current", active);
            link.setAttribute("aria-current", active ? "true" : "false");
          });
        });
      }, { rootMargin: "-50% 0px -50% 0px", threshold: 0 });
      document.querySelectorAll("article > section[id]").forEach(function (section) { tocObserver.observe(section); });
    }
  }
})();
