"""Generates the animated README graphics in assets/.

Dark cards, a serif display headline, sans UI text, a globe of scrolling
hashes with a rim fading from dusty rose to green, and accent dots from the
logo palette. Everything animates with SMIL and CSS only: GitHub renders README
SVGs through <img>, which allows no scripts and no external fonts.

    python3 tools/readme-art.py            # writes assets/*.svg
    python3 tools/readme-art.py <dir>      # writes somewhere else

Colours, fonts and copy are constants and literals below; change them here
and regenerate rather than editing the SVGs by hand.
"""
import math
import os
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "assets")

BG = "#0a0a0a"
CARD_EDGE = "#1d1d1d"
PANEL = "#111111"
PANEL_EDGE = "#262626"
INK = "#f5f5f4"
MUTED = "#8b8b8b"
FAINT = "#3a3a3a"
ROSE = "#d8a7b8"
SAGE = "#b9c4a8"
GREEN = "#4ade80"
ACCENT = "#22c55e"
DOTS = {  # logo palette
    "magenta": "#d946ef",
    "yellow": "#facc15",
    "coral": "#fb7185",
    "blue": "#3b82f6",
    "green": "#22c55e",
    "violet": "#8b5cf6",
}

SERIF = "'Tiempos Headline','Iowan Old Style','Palatino Linotype',Palatino,Georgia,'Times New Roman',serif"
SANS = "Inter,-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
MONO = "ui-monospace,'SF Mono',SFMono-Regular,Menlo,Consolas,monospace"

STYLE_BASE = f"""
    .serif {{ font-family: {SERIF}; }}
    .sans {{ font-family: {SANS}; }}
    .mono {{ font-family: {MONO}; }}
    @media (prefers-reduced-motion: reduce) {{ .m {{ animation: none !important; }} }}
"""


def f(x):
    return f"{x:.1f}".rstrip("0").rstrip(".")


def wordmark(x, y, h=34.0, stroke=3.0, track=13.0, slant=0.0):
    """ASTRAEA drawn as geometric strokes, so it looks the same everywhere.

    The A's have no crossbar. Glyphs are drawn on a 34-unit cap height and
    scaled to `h`; `slant` leans them forward by that many degrees, pivoting
    on the baseline so the letters keep their place.
    """
    k = h / 34
    glyphs = {
        "A": (30, "M0 34 L15 0 L30 34"),
        "S": (24, "M23.5 6 C21 2 17 0 12 0 C5.5 0 1 3.2 1 8.8 C1 14.5 5.5 16 12 17 "
                  "C18.5 18 23.5 19.8 23.5 25.5 C23.5 31 19 34 12 34 C6.5 34 2.2 31.8 0 28"),
        "T": (26, "M0 0 H26 M13 0 V34"),
        "R": (25, "M0 34 V0 H14 C21 0 25 4 25 9.5 C25 15 21 19 14 19 H0 M13 19 L25 34"),
        "E": (22, "M22 0 H0 V34 H22 M0 17 H18"),
    }
    lean = math.tan(math.radians(slant)) * h
    out = [f'<g transform="translate({f(x + lean)} {f(y)}) skewX({f(-slant)}) scale({f(k)})" fill="none" stroke="{INK}" '
           f'stroke-width="{f(stroke / k)}" stroke-linejoin="miter" stroke-linecap="square">']
    cx = 0.0
    for ch in "ASTRAEA":
        w, d = glyphs[ch]
        out.append(f'<path transform="translate({f(cx)} 0)" d="{d}"/>')
        cx += w + track / k
    out.append("</g>")
    return "".join(out), (cx - track / k) * k


# ---------------------------------------------------------------- hero

def hashes(n, seed):
    """Hex lines that look like what the sphere holds: ledger and object hashes."""
    import hashlib
    return [hashlib.sha512(f"{seed}{i}".encode()).hexdigest()[:64].upper() for i in range(n)]


def hero():
    W, H = 1200, 480
    cx, cy, R = 930, 236, 188

    # The sphere: a shaded body and what it stores inside, hash lines scrolling up.
    lines = hashes(24, "astraea")
    step_y = 21
    block = "".join(
        f'<text x="{cx - R}" y="{f(cy - R + 14 + i * step_y)}" class="mono hash">{h}</text>'
        for i, h in enumerate(lines + lines))
    scroll = (f'<animateTransform attributeName="transform" type="translate" from="0 0" '
              f'to="0 {-step_y * len(lines)}" dur="60s" repeatCount="indefinite"/>')

    stats = [("History from ledger", "32,571"), ("Confirmed by", "80% of the UNL"), ("Cold storage", "~208 B / tx")]
    stat_svg = []
    for i, (label, value) in enumerate(stats):
        x = 64 + i * 178
        stat_svg.append(f'<text x="{x}" y="420" class="sans" font-size="13" fill="{MUTED}">{label}</text>'
                        f'<text x="{x}" y="446" class="sans" font-size="20" fill="{INK}">{value}</text>')

    chips = ["Written in Rust", "Clio 2.8 API", "Proofs you check offline", "ISC licensed"]
    chip_svg, x = [], 64
    for c in chips:
        w = 18 + len(c) * 6.9
        chip_svg.append(f'<rect x="{f(x)}" y="352" width="{f(w)}" height="26" rx="13" fill="none" stroke="{PANEL_EDGE}"/>'
                        f'<text x="{f(x + w / 2)}" y="369.5" text-anchor="middle" class="sans" font-size="12.5" fill="{INK}" opacity=".85">{c}</text>')
        x += w + 10

    mark, mark_w = wordmark(64, 70, slant=9)
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="t d">
  <title id="t">Astraea by Lending Network</title>
  <desc id="d">XRPL history you can check yourself. A sphere holds the history: lines of ledger hashes scroll inside it.</desc>
  <style>{STYLE_BASE}
    .hash {{ font-size: 11px; letter-spacing: 1.2px; fill: {SAGE}; }}
  </style>
  <defs>
    <radialGradient id="body" cx="{cx - R * .35}" cy="{cy - R * .4}" r="{R * 1.35}" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="#17231c"/>
      <stop offset=".55" stop-color="#0e1411"/>
      <stop offset="1" stop-color="{BG}"/>
    </radialGradient>
    <radialGradient id="halo" cx="{cx}" cy="{cy}" r="{R * 1.25}" gradientUnits="userSpaceOnUse">
      <stop offset=".78" stop-color="{GREEN}" stop-opacity=".07"/>
      <stop offset="1" stop-color="{GREEN}" stop-opacity="0"/>
    </radialGradient>
    <radialGradient id="fadeHash" cx="{cx}" cy="{cy}" r="{R}" gradientUnits="userSpaceOnUse">
      <stop offset=".45" stop-color="#fff" stop-opacity="1"/>
      <stop offset="1" stop-color="#fff" stop-opacity=".12"/>
    </radialGradient>
    <mask id="inside"><circle cx="{cx}" cy="{cy}" r="{R - 4}" fill="url(#fadeHash)"/></mask>
    <linearGradient id="rim" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{ROSE}" stop-opacity=".55"/>
      <stop offset=".5" stop-color="{SAGE}" stop-opacity=".25"/>
      <stop offset="1" stop-color="{GREEN}" stop-opacity=".6"/>
    </linearGradient>
  </defs>
  <rect width="{W}" height="{H}" rx="16" fill="{BG}"/>
  <rect x=".5" y=".5" width="{W - 1}" height="{H - 1}" rx="15.5" fill="none" stroke="{CARD_EDGE}"/>

  <circle cx="{cx}" cy="{cy}" r="{f(R * 1.25)}" fill="url(#halo)"/>
  <circle cx="{cx}" cy="{cy}" r="{R}" fill="url(#body)"/>
  <g mask="url(#inside)" opacity=".8"><g>{block}{scroll}</g></g>
  <circle cx="{cx}" cy="{cy}" r="{R}" fill="none" stroke="url(#rim)" stroke-width="1.2"/>

  {mark}
  <text x="{f(64 + mark_w)}" y="128" text-anchor="end" class="sans" font-size="14" fill="{MUTED}">by Lending Network</text>

  <text x="62" y="222" class="serif" font-size="54" fill="{INK}" letter-spacing="-.5">XRPL history</text>
  <text x="62" y="282" class="serif" font-size="54" fill="{INK}" letter-spacing="-.5">you can check yourself</text>
  <text x="64" y="322" class="sans" font-size="16" fill="{MUTED}">The XRPL history server that doesn&#8217;t ask you to trust it.</text>
  {''.join(chip_svg)}
  {''.join(stat_svg)}
</svg>
"""


# ---------------------------------------------------------- architecture

def architecture():
    W, H = 1000, 560

    def box(x, y, w, h, title, lines, dot=None, edge=PANEL_EDGE, title_class="sans", tsize=15):
        s = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="{PANEL}" stroke="{edge}"/>']
        tx = x + 18
        if dot:
            s.append(f'<circle cx="{x + 20}" cy="{y + 25}" r="4" fill="{dot}"/>')
            tx = x + 32
        s.append(f'<text x="{tx}" y="{y + 30}" class="{title_class}" font-size="{tsize}" font-weight="600" fill="{INK}">{title}</text>')
        for i, line in enumerate(lines):
            s.append(f'<text x="{x + 18}" y="{y + 54 + i * 19}" class="sans" font-size="12.5" fill="{MUTED}">{line}</text>')
        return "".join(s)

    src = [
        (40, 86, "xrpld (gRPC)", ["validated ledgers", "with state changes"], DOTS["blue"]),
        (40, 196, "XRPLA archive", ["full history from", "ledger 32,571"], DOTS["violet"]),
        (40, 326, "Validations stream", ["signed votes", "from validators"], DOTS["yellow"]),
        (40, 436, "UNL publishers", ["vl.ripple.com", "unl.xrplf.org"], DOTS["magenta"]),
    ]
    parts = []
    for x, y, t, l, c in src:
        parts.append(box(x, y, 220, 88, t, l, dot=c))

    parts.append(box(350, 86, 300, 198, "Ledger Engine",
                     ["tx tree must match the header root", "parent hash chain, state root per ledger",
                      "", "hot store: recent ledgers and state", "cold store: ASTJ6 segments,",
                      "about 208 bytes per transaction"], edge="#2c3d31", title_class="serif", tsize=19))
    parts.append(box(350, 326, 300, 198, "Proof Engine",
                     ["every signature checked on arrival", "UNL in force at the ledger's time",
                      "", "80% of the full UNL, for every", "list combination that applies,",
                      "or the ledger is not served"], edge="#2c3d31", title_class="serif", tsize=19))
    parts.append(box(740, 120, 220, 110, "Clio-compatible API",
                     ["JSON-RPC and WebSocket", "tx, account_tx, ledger, ..."], edge="#3a3a3a"))
    parts.append(box(740, 380, 220, 110, "Proof API",
                     ["evidence packages that", "anyone can verify offline"], edge="#3a3a3a"))

    wires = {
        "w1": (f"M260 130 C305 130 305 150 350 150", DOTS["blue"], 2.0, 0),
        "w2": (f"M260 240 C305 240 305 220 350 220", DOTS["violet"], 2.6, .8),
        "w3": (f"M260 370 C305 370 305 390 350 390", DOTS["yellow"], 1.5, 0),
        "w4": (f"M260 480 C305 480 305 460 350 460", DOTS["magenta"], 3.0, .5),
        "w5": (f"M500 326 L500 284", ACCENT, 1.4, .3),
        "w6": (f"M650 175 L740 175", INK, 1.6, 0),
        "w7": (f"M650 435 L740 435", INK, 1.8, .4),
        "w8": (f"M650 250 C700 250 690 405 740 405", SAGE, 2.4, 1.0),
    }
    w_svg, d_svg = [], []
    for wid, (d, col, dur, begin) in wires.items():
        w_svg.append(f'<path id="{wid}" d="{d}" fill="none" stroke="#2a2a2a" stroke-width="1.4"/>')
        for j in range(2 if wid in ("w3", "w6") else 1):
            b = begin + j * dur / 2
            d_svg.append(f'<circle r="3.2" fill="{col}"><animateMotion dur="{dur}s" begin="{f(b)}s" '
                         f'repeatCount="indefinite"><mpath href="#{wid}"/></animateMotion></circle>')
    caps = "".join(
        f'<text x="{x}" y="58" class="sans" font-size="11" font-weight="600" letter-spacing="2.4" fill="{MUTED}">{t}</text>'
        for x, t in ((40, "SOURCES"), (350, "ASTRAEA"), (740, "WHAT CLIENTS GET")))
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="t d">
  <title id="t">How Astraea fits together</title>
  <desc id="d">Ledgers come from xrpld and the XRPLA archive, validations and UNL lists come from the network. The Ledger Engine checks and stores ledgers, the Proof Engine confirms them by validator quorum, and both feed the Clio-compatible API and the Proof API.</desc>
  <style>{STYLE_BASE}</style>
  <rect width="{W}" height="{H}" rx="16" fill="{BG}"/>
  <rect x=".5" y=".5" width="{W - 1}" height="{H - 1}" rx="15.5" fill="none" stroke="{CARD_EDGE}"/>
  {caps}
  {''.join(w_svg)}
  {''.join(parts)}
  {''.join(d_svg)}
</svg>
"""


# ----------------------------------------------------------------- proof

def proof():
    W, H = 1000, 330
    T = 9.0  # one full loop, seconds

    def kt(*pairs):
        """values/keyTimes from (time_s, value) pairs over the loop."""
        times = ";".join(f(t / T) for t, _ in pairs)
        vals = ";".join(str(v) for _, v in pairs)
        return f'values="{vals}" keyTimes="{times}" dur="{T}s" repeatCount="indefinite"'

    def panel(x, n, title, sub):
        return (f'<rect x="{x}" y="24" width="300" height="282" rx="6" fill="{PANEL}" stroke="{PANEL_EDGE}"/>'
                f'<text x="{x + 22}" y="56" class="mono" font-size="11" fill="{MUTED}" letter-spacing="1.5">0{n}</text>'
                f'<text x="{x + 22}" y="84" class="serif" font-size="21" fill="{INK}">{title}</text>'
                f'<text x="{x + 22}" y="106" class="sans" font-size="12.5" fill="{MUTED}">{sub}</text>')

    out = []
    # 1. Quorum: 10 validators, 8 sign, the bar crosses 80% and the anchor is confirmed.
    x0 = 24
    out.append(panel(x0, 1, "Quorum on the anchor", "signatures checked against the UNL in force"))
    pal = [DOTS[k] for k in ("blue", "green", "yellow", "magenta", "coral", "violet", "blue", "green", "yellow", "magenta")]
    for i in range(10):
        cx = x0 + 34 + i * 26
        if i < 8:
            t_on = 0.4 + i * 0.32
            out.append(f'<circle cx="{cx}" cy="150" r="7" fill="{pal[i]}" opacity=".15">'
                       f'<animate attributeName="opacity" {kt((0, .15), (t_on, .15), (t_on + .15, 1), (T - .4, 1), (T, .15))}/></circle>')
        else:
            out.append(f'<circle cx="{cx}" cy="150" r="7" fill="none" stroke="{FAINT}" stroke-dasharray="2 3"/>')
    out.append(f'<text x="{x0 + 22}" y="182" class="sans" font-size="12" fill="{MUTED}">8 of 10 validators signed</text>')
    bar_x, bar_w = x0 + 22, 256
    out.append(f'<rect x="{bar_x}" y="204" width="{bar_w}" height="6" rx="3" fill="#1f1f1f"/>')
    fills = [(0, 0), (0.4, 0)] + [(0.4 + i * 0.32 + .15, f(bar_w * (i + 1) / 10)) for i in range(8)] + [(T - .4, f(bar_w * .8)), (T, 0)]
    out.append(f'<rect x="{bar_x}" y="204" height="6" rx="3" width="0" fill="{ACCENT}">'
               f'<animate attributeName="width" {kt(*fills)} calcMode="linear"/></rect>')
    mark = bar_x + bar_w * .8
    out.append(f'<line x1="{f(mark)}" y1="196" x2="{f(mark)}" y2="218" stroke="{INK}" stroke-width="1.2"/>'
               f'<text x="{f(mark)}" y="236" text-anchor="middle" class="mono" font-size="11" fill="{MUTED}">80%</text>')
    t_ok = 0.4 + 7 * 0.32 + .2
    out.append(f'<g opacity="0"><animate attributeName="opacity" {kt((0, 0), (t_ok, 0), (t_ok + .3, 1), (T - .4, 1), (T, 0))}/>'
               f'<circle cx="{x0 + 30}" cy="274" r="8" fill="{ACCENT}"/>'
               f'<path d="M{x0 + 26} 274 l3 3 l5 -6" stroke="{BG}" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
               f'<text x="{x0 + 46}" y="279" class="sans" font-size="13" font-weight="600" fill="{INK}">anchor ledger confirmed</text></g>')

    # 2. Hash chain: from the anchor back to the target, each parent_hash checked.
    x1 = 350
    out.append(panel(x1, 2, "Hash chain to the target", "each header commits to its parent"))
    names = ["target", "N+1", "N+2", "anchor"]
    bx = [x1 + 22 + i * 68 for i in range(4)]
    t2 = 3.4
    for i, (bxi, name) in enumerate(zip(bx, names)):
        edge = ACCENT if name == "anchor" else PANEL_EDGE
        out.append(f'<rect x="{bxi}" y="150" width="56" height="40" rx="4" fill="#161616" stroke="{edge}"/>'
                   f'<text x="{bxi + 28}" y="174" text-anchor="middle" class="mono" font-size="11" fill="{INK}">{name}</text>')
    for i in range(3):
        xa, xb = bx[i] + 56, bx[i + 1]
        out.append(f'<path d="M{xb} 170 L{xa + 2} 170 M{xa + 7} 166 L{xa + 2} 170 L{xa + 7} 174" stroke="{FAINT}" stroke-width="1.2" fill="none"/>')
    # the check travels anchor -> target
    for step, i in enumerate((2, 1, 0)):
        t_on = t2 + step * 0.45
        out.append(f'<rect x="{bx[i]}" y="150" width="56" height="40" rx="4" fill="none" stroke="{ACCENT}" opacity="0">'
                   f'<animate attributeName="opacity" {kt((0, 0), (t_on, 0), (t_on + .2, 1), (T - .4, 1), (T, 0))}/></rect>')
    run = f'M{bx[3] + 28} 204 L{bx[0] + 28} 204'
    length = bx[3] - bx[0]
    out.append(f'<path d="{run}" stroke="{ACCENT}" stroke-width="2" stroke-dasharray="{length}" stroke-dashoffset="{length}" fill="none">'
               f'<animate attributeName="stroke-dashoffset" {kt((0, length), (t2 - .2, length), (t2 + 1.2, 0), (T - .4, 0), (T, length))}/></path>')
    out.append(f'<text x="{x1 + 22}" y="236" class="mono" font-size="11" fill="{MUTED}">parent_hash(N+1) = hash(N)</text>')
    out.append(f'<text x="{x1 + 22}" y="279" class="sans" font-size="13" fill="{MUTED}">at most 512 headers per package</text>')

    # 3. Inclusion: leaf -> root using sibling hashes.
    x2 = 676
    out.append(panel(x2, 3, "Transaction in the tree", "sibling hashes up to the header's tx root"))
    rootx, rooty = x2 + 150, 142
    lv = [(rootx, rooty)]
    l1 = [(x2 + 90, 182), (x2 + 210, 182)]
    l2 = [(x2 + 60, 222), (x2 + 120, 222), (x2 + 180, 222), (x2 + 240, 222)]
    for (ax, ay) in l1:
        out.append(f'<line x1="{rootx}" y1="{rooty}" x2="{ax}" y2="{ay}" stroke="{FAINT}" stroke-width="1.2"/>')
    for j, (bx2, by2) in enumerate(l2):
        px, py = l1[j // 2]
        out.append(f'<line x1="{px}" y1="{py}" x2="{bx2}" y2="{by2}" stroke="{FAINT}" stroke-width="1.2"/>')
    nodes = lv + l1 + l2
    for (nx, ny) in nodes:
        out.append(f'<circle cx="{nx}" cy="{ny}" r="7" fill="#161616" stroke="#4a4a4a" stroke-width="1.2"/>')
    t3 = 5.6
    # siblings provided by the package
    for k, (sx, sy) in enumerate([l2[0], l1[1]]):
        t_on = t3 + .2 + k * .5
        out.append(f'<circle cx="{sx}" cy="{sy}" r="7" fill="{ROSE}" opacity="0">'
                   f'<animate attributeName="opacity" {kt((0, 0), (t_on, 0), (t_on + .2, 1), (T - .4, 1), (T, 0))}/></circle>')
    path = f"M{l2[1][0]} {l2[1][1]} L{l1[0][0]} {l1[0][1]} L{rootx} {rooty}"
    plen = math.dist(l2[1], l1[0]) + math.dist(l1[0], (rootx, rooty))
    out.append(f'<path d="{path}" stroke="{ACCENT}" stroke-width="2.4" fill="none" stroke-linecap="round" '
               f'stroke-dasharray="{f(plen)}" stroke-dashoffset="{f(plen)}">'
               f'<animate attributeName="stroke-dashoffset" {kt((0, f(plen)), (t3, f(plen)), (t3 + 1.0, 0), (T - .4, 0), (T, f(plen)))}/></path>')
    out.append(f'<circle cx="{l2[1][0]}" cy="{l2[1][1]}" r="7" fill="{ACCENT}"/>')
    for (nx, ny), t_on in ((l1[0], t3 + .5), ((rootx, rooty), t3 + 1.0)):
        out.append(f'<circle cx="{nx}" cy="{ny}" r="7" fill="{ACCENT}" opacity="0">'
                   f'<animate attributeName="opacity" {kt((0, 0), (t_on, 0), (t_on + .15, 1), (T - .4, 1), (T, 0))}/></circle>')
    out.append(f'<text x="{l2[1][0]}" y="246" text-anchor="middle" class="mono" font-size="11" fill="{INK}">your tx</text>')
    out.append(f'<text x="{rootx + 14}" y="{rooty + 4}" class="mono" font-size="11" fill="{MUTED}">tx root</text>')
    t_done = t3 + 1.3
    out.append(f'<g opacity="0"><animate attributeName="opacity" {kt((0, 0), (t_done, 0), (t_done + .3, 1), (T - .4, 1), (T, 0))}/>'
               f'<circle cx="{x2 + 30}" cy="274" r="8" fill="{ACCENT}"/>'
               f'<path d="M{x2 + 26} 274 l3 3 l5 -6" stroke="{BG}" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
               f'<text x="{x2 + 46}" y="279" class="sans" font-size="13" font-weight="600" fill="{INK}">no trust in the server needed</text></g>')

    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-labelledby="t d">
  <title id="t">What an evidence package proves</title>
  <desc id="d">Eight of ten validators sign the anchor ledger and the quorum bar crosses 80 percent. Parent hashes link the anchor back to the target ledger. A path of sibling hashes links the transaction to the transaction root in the target header.</desc>
  <style>{STYLE_BASE}</style>
  <rect width="{W}" height="{H}" rx="16" fill="{BG}"/>
  <rect x=".5" y=".5" width="{W - 1}" height="{H - 1}" rx="15.5" fill="none" stroke="{CARD_EDGE}"/>
  {''.join(out)}
</svg>
"""


for name, fn in (("hero.svg", hero), ("architecture.svg", architecture), ("proof.svg", proof)):
    with open(f"{OUT}/{name}", "w") as fh:
        fh.write(fn())
    print(name)
