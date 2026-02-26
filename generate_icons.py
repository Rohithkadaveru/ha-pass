"""Generate PWA icons at build time — house silhouette, no Pillow needed."""
import struct
import zlib
import os


# Must match --color-primary in static/input.css
ICON_R, ICON_G, ICON_B = 0xD9, 0x52, 0x3C  # #D9523C
# Must match --hex-bg-light in static/input.css
BG_R, BG_G, BG_B = 0xF2, 0xF0, 0xE9  # #F2F0E9


def _house_pixels(size: int, bg_opaque: bool = False):
    """Yield rows of RGBA pixel data for a house silhouette.

    If bg_opaque is True, unfilled pixels get a solid background (#F2F0E9)
    instead of transparency — required for maskable icons.
    """

    # Safe zone: 15% padding on each side → inner 70%
    pad = int(size * 0.15)
    inner = size - 2 * pad

    # Shape dimensions
    roof_h = int(inner * 0.42)
    body_h = inner - roof_h

    # Body rectangle bounds
    body_left = pad
    body_right = pad + inner - 1
    body_top = pad + roof_h
    body_bottom = pad + inner - 1

    # Roof triangle: apex at top-center, base spans the body width
    apex_x = size // 2
    apex_y = pad
    roof_base_y = body_top

    # Door cutout (transparent hole in the body)
    door_w = int(inner * 0.18)
    door_h = int(body_h * 0.40)
    door_left = (size - door_w) // 2
    door_right = door_left + door_w - 1
    door_top = body_bottom - door_h + 1
    door_bottom = body_bottom

    bg_pixel = (BG_R, BG_G, BG_B, 255) if bg_opaque else (0, 0, 0, 0)

    rows = []
    for y in range(size):
        row = bytearray(b"\x00")  # filter byte
        for x in range(size):
            filled = False

            # Check body rectangle
            if body_top <= y <= body_bottom and body_left <= x <= body_right:
                # Cut out the door
                if door_top <= y <= door_bottom and door_left <= x <= door_right:
                    filled = False
                else:
                    filled = True

            # Check roof triangle (point-in-triangle using edge tests)
            if not filled and apex_y <= y < roof_base_y:
                # Linear interpolation: at row y, the roof spans from left_edge to right_edge
                t = (y - apex_y) / (roof_base_y - apex_y) if roof_base_y != apex_y else 0
                left_edge = apex_x - t * (inner / 2)
                right_edge = apex_x + t * (inner / 2)
                if left_edge <= x <= right_edge:
                    filled = True

            if filled:
                row.extend([ICON_R, ICON_G, ICON_B, 255])
            else:
                row.extend(bg_pixel)

        rows.append(bytes(row))
    return rows


def _encode_png(size: int, rows: list[bytes]) -> bytes:
    raw = b"".join(rows)
    idat = zlib.compress(raw)

    def chunk(name: bytes, data: bytes) -> bytes:
        c = name + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    # Color type 6 = RGBA, bit depth 8
    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", idat)
        + chunk(b"IEND", b"")
    )


def make_house_png(size: int) -> bytes:
    """Create an RGBA PNG with a house silhouette on a transparent background."""
    return _encode_png(size, _house_pixels(size, bg_opaque=False))


def make_maskable_png(size: int) -> bytes:
    """Create an RGBA PNG with a house silhouette on a solid #F2F0E9 background."""
    return _encode_png(size, _house_pixels(size, bg_opaque=True))


if __name__ == "__main__":
    icons_dir = os.path.join(os.path.dirname(__file__), "static", "icons")
    os.makedirs(icons_dir, exist_ok=True)

    for size in (192, 512):
        path = os.path.join(icons_dir, f"icon-{size}.png")
        with open(path, "wb") as f:
            f.write(make_house_png(size))
        print(f"Generated {path}")

        mask_path = os.path.join(icons_dir, f"icon-maskable-{size}.png")
        with open(mask_path, "wb") as f:
            f.write(make_maskable_png(size))
        print(f"Generated {mask_path}")
