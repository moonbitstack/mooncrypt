#!/usr/bin/env python3
"""Render docs/api.html from the package interfaces and the doc comments.

The page is generated, never edited: `moon info` writes each
`pkg.generated.mbti`, this script reads those together with the `///` comments in
the sources, and the docs workflow re-runs it and fails when the committed copy
differs.

    moon info --target all
    python3 scripts/gen_api.py
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
OUT = ROOT / "docs" / "api.html"

# Families in reading order: the traits first, because everything else answers
# one, then from the primitive upwards.
FAMILIES = [
    ("spec", "Core", "The traits every package answers, and the two helpers they share"),
    ("hash", "Digests", "One-way functions, one shot or streamed"),
    ("mac", "Message authentication", "Keyed digests, from HMAC to KMAC"),
    ("sum", "Checksums", "Non-cryptographic digests for integrity against noise"),
    ("kdf", "Key derivation", "Turning one secret into the keys a protocol needs"),
    ("cipher", "Block ciphers", "Sixteen-byte blocks and the modes that chain them"),
    ("stream", "Stream ciphers", "A keystream, exclusive-ored with the message"),
    ("aead", "Authenticated encryption", "Encryption that carries its own tag"),
    ("sign", "Signatures", "Five schemes, two traits"),
    ("kex", "Key agreement", "Two parties arriving at one secret"),
    ("key", "Key files", "ASN.1, PEM, and the formats built on them"),
    ("otp", "One-time passwords", "A MAC of the clock"),
]

STREAM = {"chacha20", "xchacha20", "salsa20", "rc4"}

# Plumbing that `derive` adds. It is public, but it is not what a reader came
# for, and a page that lists it buries the functions that matter.
DERIVED = {"equal", "not_equal", "to_repr", "op_equal", "to_string", "hash"}

KIND_LABEL = {
    "fn": "fn",
    "value": "let",
    "struct": "type",
    "enum": "type",
    "error": "error",
    "trait": "trait",
    "alias": "type",
}


def family_of(path: str) -> str | None:
    parts = path.split("/")
    head = parts[0]
    if head == "internal":
        return None
    if head in {"spec", "hash", "mac", "sum", "kdf", "aead", "sign", "kex", "otp"}:
        return head
    if head == "rsa":
        return "sign"
    if head in {"key", "asn1", "curve"}:
        return "key"
    if head == "cipher":
        return "stream" if len(parts) > 1 and parts[1] in STREAM else "cipher"
    return None


# ── the interface file ─────────────────────────────────────────────────────


def parse_mbti(path: Path) -> list[dict]:
    lines = path.read_text(encoding="utf-8").splitlines()
    decls: list[dict] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.startswith("//") or line.startswith("package ") or line.startswith("import"):
            i += 1
            continue
        if line.startswith("}"):
            i += 1
            continue

        block: list[str] = []
        depth = 0
        while i < len(lines):
            current = lines[i]
            block.append(current)
            depth += current.count("{") - current.count("}")
            i += 1
            nxt = lines[i] if i < len(lines) else ""
            if depth <= 0 and (
                not nxt.strip()
                or nxt.startswith("//")
                or re.match(r"^pub(?:\s|\()", nxt)
                or nxt.startswith("priv ")
            ):
                break

        text = "\n".join(block).strip()
        decl = classify(text)
        if decl:
            decls.append(decl)
    return decls


def classify(text: str) -> dict | None:
    first = text.splitlines()[0]

    m = re.match(r"pub(?:\([a-z]+\))?\s+fn\s+([A-Za-z0-9_:]+)", first)
    if m:
        return {"kind": "fn", "name": m.group(1), "sig": text}

    m = re.match(r"pub\s+let\s+([A-Za-z0-9_]+)", first)
    if m:
        return {"kind": "value", "name": m.group(1), "sig": text}

    m = re.match(r"pub(?:\([a-z]+\))?\s+suberror\s+([A-Za-z0-9_]+)", first)
    if m:
        return {"kind": "error", "name": m.group(1), "sig": text}

    m = re.match(r"pub(?:\([a-z]+\))?\s+struct\s+([A-Za-z0-9_]+)", first)
    if m:
        return {"kind": "struct", "name": m.group(1), "sig": text, "open": "(all)" in first}

    m = re.match(r"pub(?:\([a-z]+\))?\s+enum\s+([A-Za-z0-9_]+)", first)
    if m:
        return {"kind": "enum", "name": m.group(1), "sig": text}

    m = re.match(r"pub(?:\([a-z]+\))?\s+trait\s+([A-Za-z0-9_]+)", first)
    if m:
        return {"kind": "trait", "name": m.group(1), "sig": text}

    m = re.match(r"pub(?:\([a-z]+\))?\s+typealias\s+([A-Za-z0-9_]+)", first)
    if m:
        return {"kind": "alias", "name": m.group(1), "sig": text}

    m = re.match(r"pub\s+impl\s+(.+)", first)
    if m:
        return {"kind": "impl", "name": "", "sig": m.group(1).strip()}

    return None


def attach_impls(decls: list[dict]) -> list[dict]:
    """Fold `pub impl X for Y` into the declaration of Y."""
    by_name = {d["name"]: d for d in decls if d["kind"] not in {"impl"}}
    for decl in decls:
        if decl["kind"] != "impl":
            continue
        m = re.match(r"(.+?)\s+for\s+([A-Za-z0-9_]+)", decl["sig"])
        if not m:
            continue
        target = by_name.get(m.group(2))
        if target is None:
            continue
        trait = m.group(1).strip()
        target.setdefault("impls", [])
        if trait not in target["impls"]:
            target["impls"].append(trait)
    return [d for d in decls if d["kind"] != "impl"]


# ── the doc comments ──────────────────────────────────────────────────────

DECL_NAME = [
    (re.compile(r"pub(?:\([a-z]+\))?\s+fn\s+([A-Za-z0-9_:]+)"), 1),
    (re.compile(r"pub(?:\([a-z]+\))?\s+(?:suberror|struct|enum|trait|typealias)\s+([A-Za-z0-9_]+)"), 1),
    (re.compile(r"pub\s+let\s+([A-Za-z0-9_]+)"), 1),
    (re.compile(r"fn\s+([A-Za-z0-9_]+)\s*\(\s*self\s*:\s*([A-Za-z0-9_]+)"), 2),
]


def decl_name(line: str) -> str | None:
    for pattern, group in DECL_NAME:
        m = pattern.search(line)
        if not m:
            continue
        if pattern is DECL_NAME[3][0]:
            return m.group(2) + "::" + m.group(1)
        return m.group(1)
    return None


def parse_docs(package: Path) -> dict[str, list[str]]:
    """Map a declaration name to the paragraphs above it."""
    docs: dict[str, list[str]] = {}
    for file in sorted(package.glob("*.mbt")):
        if file.name.endswith("_test.mbt") or file.name == "pkg.generated.mbti":
            continue
        lines = file.read_text(encoding="utf-8").splitlines()
        i = 0
        while i < len(lines):
            if not lines[i].startswith("///|"):
                i += 1
                continue
            block: list[str] = []
            i += 1
            while i < len(lines) and lines[i].startswith("///"):
                block.append(lines[i][3:].strip())
                i += 1
            while i < len(lines) and not lines[i].strip():
                i += 1
            if i >= len(lines):
                break
            name = decl_name(lines[i])
            if name is None:
                continue
            paragraphs: list[str] = []
            current: list[str] = []
            for line in block:
                if line == "":
                    if current:
                        paragraphs.append(" ".join(current))
                        current = []
                else:
                    current.append(line)
            if current:
                paragraphs.append(" ".join(current))
            # The first doc block wins: a later one is an override in a
            # hand-written test or a second implementation.
            if paragraphs and name not in docs:
                docs[name] = paragraphs
    return docs


SPEC = re.compile(
    r"\b(RFC\s?\d|FIPS\s?\d|SP\s?800|NIST|BIP\s?\d|ISO|ITU|SEC\s?1|PKCS|doi\.org)\b"
)


def package_note(package: Path) -> tuple[str, list[str]]:
    """The comment at the head of moon.pkg: a specification line, then prose.

    The specification is whichever paragraph names one — usually the first, but
    not always: `spec` opens with what the traits are for and names its NIST
    document a paragraph later.
    """
    pkg = package / "moon.pkg"
    head: list[str] = []
    for line in pkg.read_text(encoding="utf-8").splitlines():
        if line.startswith("//"):
            head.append(line[2:].strip())
        elif not line.strip() and not head:
            continue
        else:
            break
    while head and head[-1] == "":
        head.pop()
    if not head:
        return "", []

    paragraphs: list[list[str]] = []
    current: list[str] = []
    for line in head:
        if line == "":
            if current:
                paragraphs.append(current)
                current = []
        else:
            current.append(line)
    if current:
        paragraphs.append(current)

    spec = ""
    kept: list[str] = []
    for paragraph in paragraphs:
        text = " ".join(paragraph)
        if not spec and SPEC.search(text):
            spec = text
        else:
            kept.append(text)
    return spec, kept


# ── rendering ─────────────────────────────────────────────────────────────


def esc(text: str) -> str:
    return html.escape(text, quote=False)


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def render_sig(decl: dict) -> str:
    sig = decl["sig"]
    if decl["kind"] == "struct" and not decl.get("open"):
        sig = sig.splitlines()[0]
    return esc(sig)


def render_item(decl: dict, docs: dict[str, list[str]], anchor: str) -> str:
    name = decl["name"]
    qualified = name.split("::")
    if len(qualified) > 1:
        label = (
            '<span class="dim">' + esc("::".join(qualified[:-1])) + "::</span>"
            + esc(qualified[-1])
        )
    else:
        label = esc(name)

    body = ['<div class="sig">' + render_sig(decl) + "</div>"]

    for paragraph in docs.get(name, []):
        body.append("<p>" + esc(paragraph) + "</p>")

    if decl.get("impls"):
        traits = ", ".join("<code>" + esc(t) + "</code>" for t in decl["impls"])
        body.append('<div class="sig">implements ' + traits + "</div>")

    return (
        '<div class="item" id="'
        + anchor
        + '">\n<div class="name"><span class="kind">'
        + KIND_LABEL[decl["kind"]]
        + "</span>"
        + label
        + '</div>\n<div class="body">'
        + "".join(body)
        + "</div>\n</div>"
    )


def render_package(path: str, number: int) -> str:
    package = SRC / path
    decls = attach_impls(parse_mbti(package / "pkg.generated.mbti"))
    docs = parse_docs(package)
    spec, paragraphs = package_note(package)

    # Types before values before functions: a reader looks up the type first.
    order = {"trait": 0, "struct": 1, "enum": 2, "error": 3, "alias": 4, "value": 5, "fn": 6}
    decls.sort(key=lambda d: (order.get(d["kind"], 9), d["name"]))

    items = []
    for decl in decls:
        if decl["kind"] == "fn" and decl["name"].split("::")[-1] in DERIVED:
            if not docs.get(decl["name"]):
                continue
        items.append(render_item(decl, docs, slug(path + "-" + decl["name"])))

    note = ""
    if spec:
        note += '<p class="pkg-ref">' + esc(spec) + "</p>"
    for paragraph in paragraphs:
        note += '<p class="pkg-note">' + esc(paragraph) + "</p>"

    return (
        '<section class="pkg">\n<div class="pkg-head">'
        + '<span class="no">' + str(number).zfill(2) + "</span>"
        + "<h2>" + esc(path.split("/")[-1]) + "</h2>"
        + '<span class="path">moonbitstack/mooncrypt/' + esc(path) + "</span>"
        + "</div>"
        + note
        + "\n"
        + "\n".join(items)
        + "\n</section>"
    )


def collect() -> list[tuple[str, str, str, list[str]]]:
    by_family: dict[str, list[str]] = {key: [] for key, _, _ in FAMILIES}
    for pkg in sorted(SRC.rglob("moon.pkg")):
        path = pkg.parent.relative_to(SRC).as_posix()
        if path.startswith("examples"):
            continue
        family = family_of(path)
        if family:
            by_family[family].append(path)
    out = []
    for key, title, blurb in FAMILIES:
        if by_family[key]:
            out.append((key, title, blurb, sorted(by_family[key])))
    return out


TEMPLATE = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>API reference — mooncrypt</title>
    <meta
      name="description"
      content="Every public type, value, function and trait in mooncrypt, grouped by package."
    />
    <link rel="icon" href="favicon.svg" type="image/svg+xml" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=Azeret+Mono:wght@400;500;600;700&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="assets/site.css?v=2" />
    <script>
      (() => {
        try {
          const saved = localStorage.getItem("mooncrypt-theme");
          const dark = !window.matchMedia("(prefers-color-scheme: light)").matches;
          document.documentElement.dataset.theme = saved || (dark ? "dark" : "light");
        } catch (e) {
          document.documentElement.dataset.theme = "dark";
        }
      })();
    </script>
  </head>

  <body>
    <header class="head">
      <div class="wrap">
        __BRAND__
        <span class="head-rule" aria-hidden="true"></span>
        <nav class="nav" aria-label="Site">
          <a href="guide.html"><span class="word">Guide</span></a>
          <a href="showcase.html"><span class="word">Showcase</span></a>
          <a href="api.html" aria-current="page"><span class="word">API</span></a>
          <button class="lamp-sw" data-theme-toggle aria-pressed="false" title="Switch the lamp">
            <i aria-hidden="true"></i><span class="word">lamp</span>
          </button>
          <a class="icon-link" href="https://github.com/moonbitstack/mooncrypt" aria-label="Repository on GitHub">__GITHUB__</a>
        </nav>
      </div>
    </header>

    <div class="doc-head">
      <div class="wrap">
        <span class="stamp">Reference</span>
        <h1>Every package, in order</h1>
        <p class="lede">
          Generated from each package's interface file and the comments above its
          declarations. __COUNT__ public declarations across __PACKAGES__
          packages.
        </p>
      </div>
    </div>

    <div class="wrap">
      <div class="doc-shell">
        <aside class="rail" aria-label="Contents">
          <div class="rail-title">Families</div>
          <ol>
__RAIL__
          </ol>
        </aside>

        <div class="prose api">
__INDEX__
__BODY__
        </div>
      </div>
    </div>

    <footer class="foot">
      <div class="wrap">
        <span>mooncrypt · Apache-2.0</span>
        <a href="https://github.com/moonbitstack/mooncrypt">Repository</a>
        <a href="guide.html">Guide</a>
        <a href="api.html">API</a>
        <span class="spacer">No trackers, no cookies, no analytics</span>
      </div>
    </footer>

    <script src="assets/site.js"></script>
  </body>
</html>
"""

BRAND = """<a class="brand" href="index.html">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <circle cx="12" cy="12" r="7" fill="none" stroke="currentColor" stroke-width="1.5" />
            <circle cx="12" cy="12" r="2.2" fill="currentColor" />
            <g stroke="currentColor" stroke-width="1.7">
              <path d="M12 3.6V1" />
              <path d="M17.94 6.06 19.78 4.22" />
              <path d="M20.4 12H23" />
              <path d="M17.94 17.94 19.78 19.78" />
              <path d="M12 20.4V23" />
              <path d="M6.06 17.94 4.22 19.78" />
              <path d="M3.6 12H1" />
              <path d="M6.06 6.06 4.22 4.22" />
            </g>
          </svg>
          mooncrypt
        </a>"""

GITHUB = """<svg viewBox="0 0 16 16" aria-hidden="true">
              <path
                fill="currentColor"
                d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z"
              />
            </svg>"""


def main() -> int:
    families = collect()
    rail: list[str] = []
    index: list[str] = []
    body: list[str] = []
    count = 0
    packages = 0

    for position, (key, title, blurb, paths) in enumerate(families, start=1):
        rail.append(
            '            <li><a href="#%s"><span class="n">%s</span>%s</a></li>'
            % (key, str(position).zfill(2), esc(title))
        )
        index.append('<a href="#%s">%s</a>' % (key, esc(title)))

        body.append(
            '<h2 id="%s"><span class="no">%s</span> %s</h2>\n<p class="lede">%s</p>'
            % (key, str(position).zfill(2), esc(title), esc(blurb))
        )

        for number, path in enumerate(paths, start=1):
            body.append(render_package(path, number))
            packages += 1
            count += body[-1].count('class="item"')

    page = TEMPLATE.replace("__BRAND__", BRAND)
    page = page.replace("__GITHUB__", GITHUB)
    page = page.replace("__RAIL__", "\n".join(rail))
    page = page.replace("__INDEX__", '<nav class="api-index">\n' + "\n".join(index) + "\n</nav>")
    page = page.replace("__BODY__", "\n".join(body))
    page = page.replace("__COUNT__", str(count))
    page = page.replace("__PACKAGES__", str(packages))

    OUT.parent.mkdir(parents=True, exist_ok=True)
    # Write LF explicitly: the file is compared byte for byte in CI, and a
    # Windows default of CRLF would make every line differ on Linux.
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(page)
    print("api.html: %d packages, %d declarations" % (packages, count))
    return 0


if __name__ == "__main__":
    sys.exit(main())
