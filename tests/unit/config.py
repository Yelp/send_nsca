import mock
from testify import TestCase, run, setup, assert_equal, assert_raises
import tempfile

import send_nsca

from .. import util


class TestConfig(TestCase):
    @setup
    def create_sr(self):
        self.sr = send_nsca.nsca.NscaSender("test_host")

    def test_ignores_comments(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write("""
password = 1234
# password = 2345
            """)
            f.flush()
            self.sr.parse_config(f.name)
            assert_equal(self.sr.password, "1234")

    def test_password_limits(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write("password = ")
            f.write(util.get_chrs(513))
            f.write("\n")
            f.flush()
            assert_raises(send_nsca.nsca.ConfigParseError, self.sr.parse_config, f.name)

    def test_yells_at_random_keys(self):
        with tempfile.NamedTemporaryFile() as f:
            f.write("foo = bar\n")
            f.flush()
            assert_raises(send_nsca.nsca.ConfigParseError, self.sr.parse_config, f.name)

    def test_get_encryption_method(self):
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
            with tempfile.NamedTemporaryFile() as f:
                f.write("encryption_method = %d\n" % crypter)
                f.flush()
                if success:
                    self.sr.parse_config(f.name)
                    assert_equal(self.sr.encryption_method_i, crypter)
                else:
                    assert_raises(send_nsca.nsca.ConfigParseError, self.sr.parse_config, f.name)

if __name__ == '__main__':
    run()

