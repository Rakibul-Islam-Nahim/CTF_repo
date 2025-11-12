#!/usr/bin/env python3
import math, base64, argparse, sys
import xml.etree.ElementTree as ET

def parse_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        try:
            return float(str(v).rstrip('px'))
        except Exception:
            return default

def get_coords(line):
    return tuple(parse_float(line.attrib.get(k, "0")) for k in ("x1","y1","x2","y2"))

def stroke_width(elem):
    v = elem.attrib.get('stroke-width') or elem.attrib.get('{http://www.w3.org/2000/svg}stroke-width')
    if v is None:
        return 1.0
    try:
        return float(str(v).rstrip('px'))
    except Exception:
        return 1.0

def find_namespace(root):
    if '}' in root.tag:
        ns = root.tag.split('}')[0].strip('{')
    else:
        ns = "http://www.w3.org/2000/svg"
    return {'svg': ns}

def angle_to_dir(x1, y1, x2, y2):
    dx, dy = (x2 - x1), (y2 - y1)
    # Flip dy because SVG y-axis increases downward
    ang = math.degrees(math.atan2(-dy, dx)) % 360.0
    # Snap to one of 8 directions (0..7) at 45° steps, with 0 = right
    return int((ang + 22.5) // 45) % 8

def puzzle_transform(v):
    # Mirror then rotate +2 steps (i.e., +90°)
    return ((8 - v) % 8 + 2) % 8

def cluster_by_center(lines, center_round=0.5):
    # Group lines by rounded (x1,y1) to associate two hands per clock
    def r(v): return round(v / center_round) * center_round
    groups = {}
    for ln in lines:
        x1, y1, x2, y2 = get_coords(ln)
        key = (r(x1), r(y1))
        groups.setdefault(key, []).append(ln)
    # keep only groups that look like clocks (>=2 lines)
    return {k: v for k, v in groups.items() if len(v) >= 2}

def read_order(keys, mode="grid"):
    if mode == "grid":
        # top-to-bottom, then left-to-right
        return sorted(keys, key=lambda p: (p[1], p[0]))
    elif mode == "x":
        return sorted(keys, key=lambda p: (p[0], p[1]))
    else:
        return sorted(keys)

def b64_from_vals(vals):
    table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    b64 = "".join(table[v] for v in vals if 0 <= v <= 63)
    # pad to multiple of 4
    pad_len = (4 - len(b64) % 4) % 4
    return b64 + ("=" * pad_len)

def decode_svg(svg_path, center_round=0.5, order="grid", debug=False):
    tree = ET.parse(svg_path)
    root = tree.getroot()
    ns = find_namespace(root)
    lines = list(root.findall(".//svg:line", ns))
    if not lines:
        raise RuntimeError("No <line> elements found in SVG (are hands drawn with <path>?)")

    groups = cluster_by_center(lines, center_round=center_round)
    if not groups:
        raise RuntimeError("No line clusters by centers found. Try a larger --center-round (e.g., 1.0 or 2.0).")

    vals = []
    for key in read_order(list(groups.keys()), mode=order):
        hands = sorted(groups[key], key=stroke_width, reverse=True)[:2]
        if len(hands) < 2:
            continue
        thick, thin = sorted(hands, key=stroke_width, reverse=True)

        A = angle_to_dir(*get_coords(thick))  # thick → high bits
        B = angle_to_dir(*get_coords(thin))   # thin  → low bits

        # Apply the puzzle-specific transform
        A = puzzle_transform(A)
        B = puzzle_transform(B)

        if debug:
            print(f"center={key} -> raw(A,B)={A},{B}")

        vals.append((A << 3) | B)

    b64 = b64_from_vals(vals)
    try:
        decoded = base64.b64decode(b64, validate=False)
        return b64.rstrip("="), decoded
    except Exception as e:
        raise RuntimeError(f"Base64 decode error: {e}")

def main():
    ap = argparse.ArgumentParser(description="Decode this clock-cipher SVG (with puzzle-specific transform).")
    ap.add_argument("svg", help="Path to SVG file (e.g., clockwork.svg)")
    ap.add_argument("--center-round", type=float, default=0.5, help="Rounding for centers (default 0.5 px)")
    ap.add_argument("--order", choices=["grid","x"], default="grid", help="Reading order: grid=y→x (default) or x→y")
    ap.add_argument("--raw", action="store_true", help="Print raw bytes instead of UTF-8 text")
    ap.add_argument("--debug", action="store_true", help="Print per-clock details")
    args = ap.parse_args()

    b64, decoded = decode_svg(args.svg, center_round=args.center_round, order=args.order, debug=args.debug)
    print("Base64:", b64)
    if args.raw:
        print("Decoded (raw):", decoded)
    else:
        try:
            print("Decoded (utf-8):", decoded.decode("utf-8", errors="replace"))
        except Exception:
            print("Decoded (raw):", decoded)

if __name__ == "__main__":
    main()
