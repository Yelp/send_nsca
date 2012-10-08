import mock
from testify import TestCase, run, setup_teardown, assert_raises

import send_nsca

from .. import util


class TestLimits(TestCase):
    @setup_teardown
    def create_sr(self):
        self.sr = send_nsca.nsca.NscaSender(remote_host='test')
        mock_connect = mock.Mock()
        with mock.patch.object(self.sr, 'connect', mock_connect):
            yield

    def test_hostname(self):
        self.sr.send_host(util.get_chrs(63), 0, 'ok')
        self.sr.send_host(util.get_chrs(64), 0, 'ok')
        assert_raises(ValueError, self.sr.send_host, util.get_chrs(65), 0, 'ok')
        assert_raises(ValueError, self.sr.send_host, u"\xff\xf302", 0, 'ok')

    def test_service_name(self):
        self.sr.send_service("test_host", util.get_chrs(127), 0, 'ok')
        self.sr.send_service("test_host", util.get_chrs(128), 0, 'ok')
        assert_raises(ValueError, self.sr.send_service, "test_host", util.get_chrs(129), 0, 'ok')
        assert_raises(ValueError, self.sr.send_service, "test_host", u"\xff\xf302", 0, 'ok')

    def test_output(self):
        self.sr.send_host("test_host", 0, "ok")
        assert_raises(ValueError, self.sr.send_host, "test_host", 0, util.get_chrs(513))
        self.sr.send_service("test_host", "test_service", 0, 'ok')
        assert_raises(ValueError, self.sr.send_service, "test_host", "test_service", 0, util.get_chrs(513))

    def test_code(self):
        self.sr.send_host("test_host", 0, "ok")
        assert_raises(ValueError, self.sr.send_host, "test_host", 4, "ok")

if __name__ == '__main__':
    run()
