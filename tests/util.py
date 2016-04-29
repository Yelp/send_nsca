def get_chrs(length):
    s = ''.join([chr(x % 128 + 64) for x in range(length)])
    if not isinstance(s, bytes):
        return s.encode('latin1')
    else:
        return s
