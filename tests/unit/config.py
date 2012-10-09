import cStringIO
import mock
import tempfile
from testify import assert_equal, assert_raises, run, setup, TestCase

import send_nsca

from .. import util


class TestConfig(TestCase):
    @setup
    def create_sender(self):
        self.sender = send_nsca.nsca.NscaSender("test_host", config_path=None)

    def test_ignores_comments(self):
        stream = cStringIO.StringIO()
        stream.write("""
password = 1234
# password = 2345
        """)
        self.sender.parse_config(stream)
        assert_equal(self.sender.password, "1234")

    def test_password_limits(self):
        stream = cStringIO.StringIO()
        stream.write("password = ")
        stream.write(util.get_chrs(513))
        stream.write("\n")
        assert_raises(send_nsca.nsca.ConfigParseError, self.sender.parse_config, stream)

    def test_yells_at_random_keys(self):
        stream = cStringIO.StringIO()
        stream.write("foo = bar\n")
        assert_raises(send_nsca.nsca.ConfigParseError, self.sender.parse_config, stream)

    def test_get_encryption_method(self):
        # map from crypter id to whether or not it should succeed
        crypters = {
            0: True,
            1: True,
            2: True,
            3: True,
            4: True,
            5: False,
            6: False,
            7: False,
            8: True,
            9: False,
            10: False,
            14: True,
            15: True,
            16: True,
            255: False
        }
        for crypter, success in crypters.iteritems():
            stream = cStringIO.StringIO()
            stream.write("encryption_method = %d\n" % crypter)
            if success:
                self.sender.parse_config(stream)
                assert_equal(self.sender.encryption_method_i, crypter)
            else:
                assert_raises(send_nsca.nsca.ConfigParseError, self.sender.parse_config, stream)

if __name__ == '__main__':
    run()

