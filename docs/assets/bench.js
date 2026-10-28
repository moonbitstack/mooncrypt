// mooncrypt — the showcase.
//
// Three instruments, each one running the library compiled to JavaScript. No
// second implementation of anything: every number below comes out of a package.

(() => {
  "use strict";

  const lib = window.mooncrypt;
  const missing = document.querySelectorAll("[data-needs-lib]");

  if (!lib) {
    missing.forEach((node) => {
      node.textContent =
        "The compiled library is not in this checkout. " +
        "Build it with `moon build --target js --release src/examples/browser` " +
        "and copy the result to docs/assets/mooncrypt.js.";
    });
    return;
  }

  const utf8 = (text) => {
    let out = "";
    for (const b of new TextEncoder().encode(text)) out += b.toString(16).padStart(2, "0");
    return out;
  };

  const bytes = (hex) => {
    const out = [];
    for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.slice(i, i + 2), 16) || 0);
    return out;
  };

  const fromBytes = (list) =>
    list.map((b) => b.toString(16).padStart(2, "0")).join("");

  /* ── 01 · avalanche ───────────────────────────────────────────────────── */

  const avInput = document.getElementById("av-input");
  const avBit = document.getElementById("av-bit");
  const avGrid = document.getElementById("av-grid");
  const avBitOut = document.getElementById("av-bit-out");
  const avCount = document.getElementById("av-count");
  const avA = document.getElementById("av-a");
  const avB = document.getElementById("av-b");

  const cells = [];
  if (avGrid) {
    for (let i = 0; i < 256; i++) {
      const cell = document.createElement("i");
      avGrid.appendChild(cell);
      cells.push(cell);
    }
  }

  const flip = (hex, bit) => {
    const list = hex === "" ? [0] : bytes(hex);
    list[0] = list[0] ^ (1 << bit);
    return fromBytes(list);
  };

  const avalanche = () => {
    if (!avInput) return;
    const base = utf8(avInput.value);
    const bit = Number(avBit.value);
    if (avBitOut) avBitOut.textContent = bit;
    const a = lib.digest("sha256", base);
    const b = lib.digest("sha256", flip(base, bit));
    if (!a || !b) return;

    const left = bytes(a);
    const right = bytes(b);
    let changed = 0;

    for (let col = 0; col < 32; col++) {
      const diff = left[col] ^ right[col];
      for (let row = 0; row < 8; row++) {
        const on = (diff >> row) & 1;
        if (on) changed++;
        cells[row * 32 + col].classList.toggle("on", on === 1);
      }
    }

    avCount.textContent = changed;
    avA.textContent = a;
    avB.textContent = b;
  };

  if (avInput) {
    avInput.addEventListener("input", avalanche);
    avBit.addEventListener("input", avalanche);
    avalanche();
  }

  /* ── 02 · a tag that refuses ──────────────────────────────────────────── */

  const tgInput = document.getElementById("tg-input");
  const tgHex = document.getElementById("tg-hex");
  const tgVerdict = document.getElementById("tg-verdict");
  const tgButton = document.getElementById("tg-tamper");
  const tgPlain = document.getElementById("tg-plain");

  const key = "2b".repeat(16);
  const nonce = "00".repeat(12);
  let sealed = "";
  let tampered = false;

  const paint = (hex, hot) => {
    const parts = [];
    for (let i = 0; i < hex.length; i += 2) {
      const byte = hex.slice(i, i + 2);
      parts.push(i / 2 === hot ? `<span class="hot">${byte}</span>` : byte);
    }
    const groups = [];
    for (let i = 0; i < parts.length; i += 8) groups.push(parts.slice(i, i + 8).join(" "));
    return groups.join("\n");
  };

  const reseal = () => {
    if (!tgInput) return;
    sealed = lib.seal("aes-gcm", key, nonce, utf8(tgInput.value));
    tampered = false;
    judge();
  };

  const judge = () => {
    if (!sealed) return;
    let probe = sealed;
    if (tampered) {
      const list = bytes(sealed);
      list[0] = list[0] ^ 0x01;
      probe = fromBytes(list);
    }

    tgHex.innerHTML = paint(probe, tampered ? 0 : -1);

    const answer = lib.open("aes-gcm", key, nonce, probe);
    if (answer === "!refused") {
      tgVerdict.textContent = "refused — nothing returned";
      tgVerdict.className = "verdict-line no";
      tgPlain.textContent = "";
    } else {
      const text = new TextDecoder().decode(
        new Uint8Array(answer ? bytes(answer) : [])
      );
      tgVerdict.textContent = "opened";
      tgVerdict.className = "verdict-line ok";
      tgPlain.textContent = text;
    }
  };

  if (tgInput) {
    tgInput.addEventListener("input", reseal);
    tgButton.addEventListener("click", () => {
      tampered = !tampered;
      tgButton.textContent = tampered ? "put it back" : "flip one bit";
      judge();
    });
    reseal();
  }

  /* ── 03 · a one-time password ─────────────────────────────────────────── */

  const otpCode = document.getElementById("otp-code");
  const otpArc = document.getElementById("otp-arc");
  const otpLeft = document.getElementById("otp-left");
  const otpSecret = "3132333435363738393031323334353637383930";
  const circumference = 2 * Math.PI * 52;

  const tick = () => {
    if (!otpCode) return;
    const now = Math.floor(Date.now() / 1000);
    const code = lib.totp(otpSecret, now);
    const left = 30 - (now % 30);

    if (code) otpCode.textContent = code;
    otpLeft.textContent = left + "s";

    if (otpArc) {
      const used = (30 - left) / 30;
      otpArc.setAttribute("stroke-dasharray", `${circumference * used} ${circumference}`);
      otpArc.setAttribute("stroke-dashoffset", "0");
    }
  };

  if (otpCode) {
    tick();
    setInterval(tick, 250);
  }

  /* ── the stamps ───────────────────────────────────────────────────────── */

  document.querySelectorAll("[data-stamp]").forEach((node) => {
    node.textContent = new Date().toISOString().slice(11, 19) + " UTC";
  });
})();
