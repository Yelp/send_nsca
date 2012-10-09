def get_chrs(length):
    return ''.join([chr(x % 128 + 64) for x in xrange(length)])
