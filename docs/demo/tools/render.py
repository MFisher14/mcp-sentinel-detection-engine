"""Replay a cast through pyte (with scrollback) and dump/render line ranges."""
import html, json, sys, pyte

def replay(path):
    lines = open(path).read().splitlines()
    h = json.loads(lines[0])
    screen = pyte.HistoryScreen(h["width"], h["height"], history=20000, ratio=0.001)
    stream = pyte.Stream(screen)
    for l in lines[1:]:
        stream.feed(json.loads(l)[2])
    rows = [ [line[x] for x in range(h["width"])] for line in screen.history.top ]
    rows += [ [screen.buffer[y][x] for x in range(h["width"])] for y in range(h["height"]) ]
    return h["width"], rows

PALETTE = {"black":"#1e1e1e","red":"#f47067","green":"#8ddb8c","brown":"#f2cc60","yellow":"#f2cc60",
           "blue":"#6cb6ff","magenta":"#dcbdfb","cyan":"#96d0ff","white":"#d1d7e0","default":"#d1d7e0"}
BG = "#16181d"

def color(c, fg=True):
    if c == "default": return None
    if c in PALETTE: return PALETTE[c]
    if len(c) == 6: return "#" + c
    if c.startswith("bright"): return PALETTE.get(c[6:], None)
    return None

def to_html(width, rows, a, b, title):
    out = []
    for row in rows[a:b]:
        spans = []; cur = None; buf = ""
        for ch in row:
            fg = color(ch.fg) or PALETTE["default"]
            bg = color(ch.bg, False) if ch.bg != "default" else None
            if ch.reverse: fg, bg = (bg or BG), fg
            style = f"color:{fg};" + (f"background:{bg};" if bg else "") + ("font-weight:700;" if ch.bold else "") + ("font-style:italic;" if ch.italics else "")
            if ch.data == "": continue
            if style != cur and buf:
                spans.append(f'<span style="{cur}">{html.escape(buf)}</span>'); buf = ""
            cur = style; buf += ch.data
        if buf: spans.append(f'<span style="{cur}">{html.escape(buf)}</span>')
        out.append("".join(spans) or " ")
    body = "\n".join(out)
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#0d1117;padding:28px;display:inline-block}}
.win{{background:{BG};border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.5);overflow:hidden;border:1px solid #2d333b}}
.bar{{height:30px;background:#22262e;display:flex;align-items:center;padding:0 12px;gap:8px;font:12px -apple-system,Helvetica,sans-serif;color:#8b949e}}
.d{{width:12px;height:12px;border-radius:50%}}.t{{flex:1;text-align:center;margin-right:52px}}
pre{{margin:0;padding:14px 18px 18px;font:13.5px/1.38 Menlo,"SF Mono",monospace;white-space:pre;color:{PALETTE['default']}}}
</style></head><body><div class="win"><div class="bar"><span class="d" style="background:#ff5f57"></span><span class="d" style="background:#febc2e"></span><span class="d" style="background:#28c840"></span><span class="t">{html.escape(title)}</span></div><pre>{body}</pre></div></body></html>"""

if __name__ == "__main__":
    width, rows = replay(sys.argv[1])
    if sys.argv[2] == "dump":
        for i, r in enumerate(rows):
            print(f"{i:4d} " + "".join(c.data for c in r).rstrip())
    else:
        a, b, out, title = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
        open(out, "w").write(to_html(width, rows, a, b, title))
