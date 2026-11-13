import json, sys, pyte
sys.path.insert(0, ".")
from render import to_html
path, t, out, title = sys.argv[1], float(sys.argv[2]), sys.argv[3], sys.argv[4]
a = int(sys.argv[5]) if len(sys.argv) > 5 else 0
b = int(sys.argv[6]) if len(sys.argv) > 6 else None
lines = open(path).read().splitlines()
h = json.loads(lines[0]); screen = pyte.Screen(h["width"], h["height"]); stream = pyte.Stream(screen)
for l in lines[1:]:
    e = json.loads(l)
    if e[0] > t: break
    stream.feed(e[2])
rows = [[screen.buffer[y][x] for x in range(h["width"])] for y in range(h["height"])]
open(out, "w").write(to_html(h["width"], rows, a, b if b is not None else h["height"], title))
print("\n".join(f"{i:2d} " + "".join(c.data for c in r).rstrip() for i, r in enumerate(rows[a:b], start=a)))
