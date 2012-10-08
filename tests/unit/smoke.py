import mock
from testify import TestCase, run, assert_equal

import send_nsca

def mock_random_alphanumeric_bytes(bytesz):
    return ''.join([chr(x % 74 + 48) for x in xrange(bytesz)])

class SmokeTestCase(TestCase):
    """Some random smoke tests"""

    def test_pack_packet_all(self):
        vectors = [
                (("test_host", "test_service", 0, "foo", 0), '\x00\x03\x00\x00\x8c\xce\x07\x98\x00\x00\x00\x00\x00\x00test_host\x000123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdetest_service\x000123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXfoo\x000123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmno\x00\x00'),
                (("0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQAAAAAAAAAAAAAAAA", "test_service", 0, "foo", 0), '\x00\x03\x00\x00\xeb\xdf\x02w\x00\x00\x00\x00\x00\x000123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnotest_service\x000123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXfoo\x000123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxy0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmno\x00\x00')
        ]
        with mock.patch('send_nsca.nsca.get_random_alphanumeric_bytes', mock_random_alphanumeric_bytes):
            for args, result in vectors:
                try:
                    assert_equal(send_nsca.nsca._pack_packet(*args), result)
                except:
                    print repr(send_nsca.nsca._pack_packet(*args))

if __name__ == '__main__':
    run()
