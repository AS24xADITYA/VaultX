from PIL import Image
import struct

MAGIC_HEADER = b'VLTX'

def hide_data_in_image(carrier_image_path: str, secret_bytes: bytes, output_path: str) -> None:
    """
    Embed `secret_bytes` into the carrier image using LSB steganography.
    """
    img = Image.open(carrier_image_path).convert('RGB')
    pixels = list(img.getdata())
    
    payload = MAGIC_HEADER + struct.pack('>I', len(secret_bytes)) + secret_bytes
    bits = ''.join(f'{byte:08b}' for byte in payload)
    
    if len(bits) > len(pixels) * 3:
        raise ValueError(f"Image too small. Need {len(bits)//3} pixels, have {len(pixels)}.")
    
    new_pixels = []
    bit_idx = 0
    for r, g, b in pixels:
        if bit_idx < len(bits):
            r = (r & 0xFE) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits):
            g = (g & 0xFE) | int(bits[bit_idx]); bit_idx += 1
        if bit_idx < len(bits):
            b = (b & 0xFE) | int(bits[bit_idx]); bit_idx += 1
        new_pixels.append((r, g, b))
    
    result = Image.new('RGB', img.size)
    result.putdata(new_pixels)
    result.save(output_path, 'PNG')

def extract_data_from_image(image_path: str) -> bytes:
    """
    Extract hidden bytes from a steganographic image.
    """
    img = Image.open(image_path).convert('RGB')
    pixels = list(img.getdata())
    bits = ''
    for r, g, b in pixels:
        bits += str(r & 1) + str(g & 1) + str(b & 1)
        
    magic = bytes(int(bits[i:i+8], 2) for i in range(0, 32, 8))
    if magic != MAGIC_HEADER:
        raise ValueError("No VaultX steganographic data found in this image.")
        
    length = struct.unpack('>I', bytes(int(bits[i:i+8], 2) for i in range(32, 64, 8)))[0]
    payload_bits = bits[64: 64 + length * 8]
    return bytes(int(payload_bits[i:i+8], 2) for i in range(0, len(payload_bits), 8))
