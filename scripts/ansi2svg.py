#!/usr/bin/env python3
"""Turn coloured terminal output (ANSI SGR codes) into an SVG picture.

    go test ./cmd/nabd -run TestDemo -count=1   (with NABD_DEMO=demo.ansi)
    python3 scripts/ansi2svg.py demo.ansi docs/demo.svg "sudo nabd"
"""
import html
import re
import sys

FG = {30: "#4b5263", 31: "#ff6b6b", 32: "#5fd38d", 33: "#f7c95c", 34: "#6cb6ff", 35: "#d59cff",
      36: "#56d4dd", 37: "#d7dae0", 90: "#7d8590", 39: None}
BASE, DIM, BG, BAR = "#d7dae0", "#8b949e", "#0d1117", "#161b22"
CW, LH, FS, PAD = 7.85, 19, 13, 22  # char width, line height, font size, padding

def parse(line):
    """Yield (text, color, bold, dim) runs."""
    color, bold, dim = None, False, False
    pos = 0
    for m in re.finditer(r"\x1b\[([0-9;]*)m", line):
        if m.start() > pos:
            yield line[pos:m.start()], color, bold, dim
        for code in (m.group(1) or "0").split(";"):
            c = int(code or 0)
            if c == 0:
                color, bold, dim = None, False, False
            elif c == 1:
                bold = True
            elif c == 2:
                dim = True
            elif c in FG:
                color = FG[c]
        pos = m.end()
    if pos < len(line):
        yield line[pos:], color, bold, dim

def main(src, dst, prompt):
    lines = open(src, encoding="utf-8").read().rstrip("\n").split("\n")
    lines = ["\x1b[32m$\x1b[0m " + prompt, ""] + lines
    cols = max(len(re.sub(r"\x1b\[[0-9;]*m", "", l)) for l in lines)
    width = int(cols * CW + 2 * PAD)
    top = 38
    height = int(top + PAD + len(lines) * LH + PAD - 6)
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="nabd output on a demo server">',
           "<style>text{font-family:ui-monospace,'SFMono-Regular','JetBrains Mono','DejaVu Sans Mono',Menlo,Consolas,monospace;font-size:%dpx;white-space:pre}</style>" % FS,
           f'<rect width="{width}" height="{height}" rx="10" fill="{BG}"/>',
           f'<path d="M0 10a10 10 0 0 1 10-10h{width-20}a10 10 0 0 1 10 10v20H0z" fill="{BAR}"/>',
           '<circle cx="20" cy="15" r="5.5" fill="#ff5f57"/><circle cx="38" cy="15" r="5.5" fill="#febc2e"/><circle cx="56" cy="15" r="5.5" fill="#28c840"/>',
           f'<text x="{width/2}" y="19.5" fill="{DIM}" text-anchor="middle" style="font-size:12px">root@web-prod-1: ~</text>']
    y = top + PAD
    for line in lines:
        x = PAD
        parts = []
        for text, color, bold, dim in parse(line):
            fill = color or (DIM if dim else BASE)
            weight = ' font-weight="700"' if bold else ""
            opacity = ' fill-opacity="0.75"' if dim and color else ""
            parts.append(f'<tspan x="{x:.1f}" fill="{fill}"{weight}{opacity}>{html.escape(text)}</tspan>')
            x += len(text) * CW
        if parts:
            out.append(f'<text y="{y}">{"".join(parts)}</text>')
        y += LH
    out.append("</svg>")
    open(dst, "w", encoding="utf-8").write("\n".join(out) + "\n")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "nabd")
