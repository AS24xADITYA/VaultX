import ctypes

def wipe_string(s: str) -> None:
    if not isinstance(s, str):
        return
    try:
        buf_len = len(s)
        addr = id(s)
        ctypes.memset(addr + 49, 0, buf_len)
    except Exception:
        pass

def wipe_bytes(b: bytes) -> None:
    if not isinstance(b, bytes):
        return
    try:
        ctypes.memset(id(b) + 33, 0, len(b))
    except Exception:
        pass

def secure_del(obj) -> None:
    if isinstance(obj, str):
        wipe_string(obj)
    elif isinstance(obj, bytes):
        wipe_bytes(obj)
    try:
        del obj
    except Exception:
        pass
