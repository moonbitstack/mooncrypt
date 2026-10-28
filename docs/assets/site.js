// mooncrypt — page behaviour.
//
// Three jobs: keep the theme, turn the hero drawing, and feed the tape from the
// library compiled to JavaScript. Nothing here reimplements a hash.

(() => {
  "use strict";

  const root = document.documentElement;
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ── the lamp ─────────────────────────────────────────────────────────── */

  const KEY = "mooncrypt-theme";

  const toggle = document.querySelector("[data-theme-toggle]");

  const paint = (on) => {
    root.setAttribute("data-theme", on ? "dark" : "light");
    if (toggle) {
      toggle.setAttribute("aria-pressed", String(on));
      const word = toggle.querySelector(".word");
      if (word) word.textContent = on ? "lamp on" : "lamp off";
    }
  };

  if (toggle) {
    paint(root.getAttribute("data-theme") !== "light");
    toggle.addEventListener("click", () => {
      const next = root.getAttribute("data-theme") !== "dark";
      try {
        localStorage.setItem(KEY, next ? "dark" : "light");
      } catch (e) {
        /* a reader with storage turned off still gets the switch */
      }
      paint(next);
    });
  }

  /* ── the rotor ────────────────────────────────────────────────────────── */

  const ring = document.getElementById("rotor");
  if (ring && !reduce) {
    let queued = false;
    const turn = () => {
      queued = false;
      ring.style.transform = `rotate(${(window.scrollY * 0.055).toFixed(2)}deg)`;
    };
    window.addEventListener(
      "scroll",
      () => {
        if (!queued) {
          queued = true;
          requestAnimationFrame(turn);
        }
      },
      { passive: true }
    );
    turn();
  }

  /* ── listings ─────────────────────────────────────────────────────────── */

  const words =
    /(\/\/[^\n]*)|("(?:[^"\\]|\\.)*")|(\b(?:fn|let|mut|pub|priv|impl|for|in|match|if|else|return|guard|try|catch|while|struct|enum|trait|type|derive|const|extern|raise|with|extend|true|false|self)\b)|(\b\d[\d_]*(?:\.\d+)?\b)/g;

  const esc = (s) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const mark = (code) => {
    const text = code.textContent;
    let out = "";
    let at = 0;
    let m;
    words.lastIndex = 0;
    while ((m = words.exec(text)) !== null) {
      out += esc(text.slice(at, m.index));
      const cls = m[1] ? "tok-c" : m[2] ? "tok-s" : m[3] ? "tok-k" : "tok-n";
      out += `<span class="${cls}">${esc(m[0])}</span>`;
      at = m.index + m[0].length;
    }
    out += esc(text.slice(at));
    code.innerHTML = out;
  };

  document.querySelectorAll("code.mark").forEach(mark);

  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const listing = button.closest(".listing");
      const text = listing ? listing.querySelector("pre").textContent : "";
      try {
        await navigator.clipboard.writeText(text);
        const was = button.textContent;
        button.textContent = "copied";
        setTimeout(() => (button.textContent = was), 1200);
      } catch (e) {
        button.textContent = "select it";
      }
    });
  });

  /* ── the tape ─────────────────────────────────────────────────────────── */

  const tape = document.getElementById("tape");
  const carriage = document.getElementById("carriage");
  if (!tape || !carriage) return;

  const rows = document.getElementById("tape-rows");
  const lamp = document.getElementById("tape-lamp");
  const count = document.getElementById("tape-count");
  const kinds = document.querySelectorAll("[data-kind]");
  const lib = window.mooncrypt;

  if (!lib) {
    rows.innerHTML =
      '<p class="dim" style="padding:0 18px;font-size:.8rem">' +
      "The compiled library is not in this checkout. Build it with " +
      "<code>moon build --target js --release src/examples/browser</code> " +
      "and copy the result to <code>docs/assets/mooncrypt.js</code>." +
      "</p>";
    return;
  }

  const utf8 = (text) => {
    const bytes = new TextEncoder().encode(text);
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0");
    return out;
  };

  let kind = "sha256";
  let shown = [];

  const rowsOf = (hex, before) => {
    const cells = document.createDocumentFragment();
    for (let i = 0; i < hex.length; i += 8) {
      const group = hex.slice(i, i + 8);
      for (let j = 0; j < group.length; j++) {
        const at = i + j;
        const changed = before && before.length === hex.length && before[at] !== hex[at];
        const node = changed ? document.createElement("b") : document.createTextNode("");
        node.textContent = group[j];
        cells.appendChild(node);
      }
      if (i + 8 < hex.length) cells.appendChild(document.createTextNode(" "));
    }
    return cells;
  };

  const draw = (digest, before, say) => {
    const row = document.createElement("div");
    row.className = "tape-row";

    const when = document.createElement("span");
    when.className = "when";
    const now = new Date();
    when.textContent =
      String(now.getHours()).padStart(2, "0") +
      ":" +
      String(now.getMinutes()).padStart(2, "0") +
      ":" +
      String(now.getSeconds()).padStart(2, "0");

    const cell = document.createElement("span");
    cell.className = "cell";

    const said = document.createElement("span");
    said.className = "say";
    said.textContent = say === "" ? "(nothing typed)" : say;

    const digestEl = document.createElement("span");
    digestEl.className = "digest";
    digestEl.appendChild(rowsOf(digest, before));

    cell.append(said, digestEl);
    row.append(when, cell);
    rows.prepend(row);

    while (rows.children.length > 3) rows.lastElementChild.remove();

    if (lamp) {
      lamp.classList.add("live");
      setTimeout(() => lamp.classList.remove("live"), 180);
    }
    if (count) {
      shown = [digest, ...shown].slice(0, 3);
      count.textContent = String(shown.length).padStart(2, "0") + " rows";
    }
  };

  let timer = 0;

  const feed = () => {
    const text = carriage.value;
    const digest = lib.digest(kind, utf8(text));
    const before = shown[0] || "";
    if (!digest) return;
    draw(digest, before, text);
  };

  carriage.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(feed, 70);
  });

  kinds.forEach((button) => {
    button.addEventListener("click", () => {
      kind = button.dataset.kind;
      kinds.forEach((other) =>
        other.setAttribute("aria-pressed", String(other === button))
      );
      shown = [];
      rows.innerHTML = "";
      feed();
    });
  });

  feed();
})();
