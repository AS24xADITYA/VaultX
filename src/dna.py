import hashlib
from PIL import Image
import io

GRID_SIZE   = 8
CELL_PX     = 16
PALETTE_DIM = (20, 32, 56)

def generate_fingerprint(password: str) -> bytes:
    """Generate an 8x8 identicon as PNG bytes from a password's SHA-256 hash."""
    digest = hashlib.sha256(password.encode('utf-8')).digest()
    
    r = max(80, digest[0])
    g = max(80, digest[1])
    b = max(80, digest[2])
    lit_color = (r, g, b)
    
    img = Image.new('RGB', (GRID_SIZE * CELL_PX, GRID_SIZE * CELL_PX), PALETTE_DIM)
    
    bit_idx = 24
    for row in range(GRID_SIZE):
        for col in range(GRID_SIZE // 2):
            bit = (digest[bit_idx // 8] >> (7 - bit_idx % 8)) & 1
            bit_idx += 1
            color = lit_color if bit else PALETTE_DIM
            
            x0 = col * CELL_PX
            y0 = row * CELL_PX
            for px in range(CELL_PX):
                for py in range(CELL_PX):
                    img.putpixel((x0 + px, y0 + py), color)
                    img.putpixel(((GRID_SIZE - 1 - col) * CELL_PX + px, y0 + py), color)
                    
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()
