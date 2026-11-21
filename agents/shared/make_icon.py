"""Render the DevMonitor app icon (original artwork) as a 1024x1024 PNG.

Pure Python (zlib + struct) so it runs anywhere:
    python agents/shared/make_icon.py agents/shared/icon-1024.png
"""

import math
import struct
import sys
import zlib

SIZE = 1024
NAVY = (15, 8, 75)
DEEP = (13, 2, 33)
WHITE = (255, 255, 255)
BLUE = (122, 162, 255)


def lerp(a, b, t):
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(3))


def distance_to_segment(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy or 1)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def rounded_rect_edge(px, py, x0, y0, x1, y1, r):
    """Distance from the outline of a rounded rectangle."""
    cx = min(max(px, x0 + r), x1 - r)
    cy = min(max(py, y0 + r), y1 - r)
    inside = x0 + r <= px <= x1 - r or y0 + r <= py <= y1 - r
    if inside and x0 <= px <= x1 and y0 <= py <= y1:
        return min(px - x0, x1 - px, py - y0, y1 - py)
    return abs(math.hypot(px - cx, py - cy) - r)


def render():
    s = SIZE / 108.0  # artwork is drawn on the Android 108-unit grid
    pulse = [(37, 54), (47, 54), (51, 46), (57, 62), (61, 54), (71, 54)]
    stand = [((46, 76), (62, 76)), ((54, 68), (54, 76))]
    rows = []
    for y in range(SIZE):
        row = bytearray([0])
        for x in range(SIZE):
            color = lerp(NAVY, DEEP, (x + y) / (2 * SIZE))
            ux, uy = x / s, y / s
            if rounded_rect_edge(ux, uy, 30, 38, 78, 68, 4) <= 2.0:
                color = WHITE
            if any(distance_to_segment(ux, uy, *a, *b) <= 2.0 for a, b in stand):
                color = WHITE
            if any(distance_to_segment(ux, uy, *pulse[i], *pulse[i + 1]) <= 2.0
                   for i in range(len(pulse) - 1)):
                color = BLUE
            row.extend(color)
        rows.append(bytes(row))
    return b"".join(rows)


def png(raw):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
    header = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "icon-1024.png"
    with open(target, "wb") as output:
        output.write(png(render()))
    print(f"wrote {target}")
