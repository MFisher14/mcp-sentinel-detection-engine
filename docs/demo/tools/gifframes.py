import json, sys, pyte
sys.path.insert(0, ".")
from render import to_html
lines = open("clean.cast").read().splitlines()
h = json.loads(lines[0]); screen = pyte.Screen(h["width"], h["height"]); stream = pyte.Stream(screen)
fps = 2; nxt = 0.0; n = 0; prev = None; durations = []
evs = [json.loads(l) for l in lines[1:]]
end = evs[-1][0] - 2.5  # drop the trailing ctrl-c exit
def emit():
    global n, prev
    disp = "\n".join(screen.display)
    if disp == prev:
        durations[-1] += 1 / fps; return
    prev = disp
    rows = [[screen.buffer[y][x] for x in range(h["width"])] for y in range(h["height"])]
    open(f"gif/f{n:04d}.html", "w").write(to_html(h["width"], rows, 0, h["height"], "Claude Code + mcp-sentinel-detection-engine (demo workspace)"))
    durations.append(1 / fps); n += 1
for e in evs:
    if e[0] > end: break
    while e[0] > nxt:
        emit(); nxt += 1 / fps
    stream.feed(e[2])
emit(); durations[-1] += 4
with open("gif/concat.txt", "w") as f:
    for i, d in enumerate(durations):
        f.write(f"file 'f{i:04d}.png'\nduration {d:.2f}\n")
    f.write(f"file 'f{len(durations)-1:04d}.png'\n")
print(n, "frames", round(sum(durations),1), "s")
