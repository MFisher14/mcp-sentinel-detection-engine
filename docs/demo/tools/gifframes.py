"""Render a cast to per-frame HTML plus an ffmpeg concat list for the GIF.

usage: gifframes.py [cast] [speed] [min_pause]

speed      playback multiplier (2 = twice as fast)
min_pause  frames the cast already holds this long (e.g. the finished
           prompt) are never sped below it, so they stay readable

The concat demuxer ignores the last frame's duration, so hold the final
frame in the encode step instead (tpad), e.g. 12 s to read the summary:

  cd gif && ffmpeg -f concat -i concat.txt -vf "fps=10,\
    tpad=stop_mode=clone:stop_duration=12,scale=900:-1:flags=lanczos,\
    split[a][b];[a]palettegen=max_colors=64[p];[b][p]paletteuse=dither=none" out.gif
"""
import json, sys, pyte
sys.path.insert(0, ".")
from render import to_html

cast = sys.argv[1] if len(sys.argv) > 1 else "clean.cast"
speed = float(sys.argv[2]) if len(sys.argv) > 2 else 2.0
min_pause = float(sys.argv[3]) if len(sys.argv) > 3 else 3.0

lines = open(cast).read().splitlines()
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
emit()
durations = [d if d >= min_pause else d / speed for d in durations]
with open("gif/concat.txt", "w") as f:
    for i, d in enumerate(durations):
        f.write(f"file 'f{i:04d}.png'\nduration {d:.2f}\n")
print(n, "frames", round(sum(durations[:-1]), 1), "s before the final-frame hold")
