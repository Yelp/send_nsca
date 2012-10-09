import mock
from testify import assert_raises, run, setup_teardown, TestCase

import send_nsca

from .. import util


class TestLimits(TestCase):
    @setup_teardown
    def create_sr(self):
        self.sr = send_nsca.nsca.NscaSender(remote_host='test', config_path=None)
        mock_connect = mock.Mock()
        with mock.patch.object(self.sr, 'connect', mock_connect):
            yield

    def test_hostname(self):
        # check that we can send valid packets
        self.sr.send_host(util.get_chrs(send_nsca.nsca.MAX_HOSTNAME_LENGTH - 1), 0, 'ok')
        self.sr.send_host(util.get_chrs(send_nsca.nsca.MAX_HOSTNAME_LENGTH), 0, 'ok')
        # check that we cannot send invalid packets
        assert_raises(ValueError, self.sr.send_host, util.get_chrs(send_nsca.nsca.MAX_HOSTNAME_LENGTH + 1), 0, 'ok')
        # ascii only
        assert_raises(ValueError, self.sr.send_host, u"\xff\xf302", 0, 'ok')

    def test_service_name(self):
        self.sr.send_service("test_host", util.get_chrs(send_nsca.nsca.MAX_DESCRIPTION_LENGTH - 1), 0, 'ok')
        self.sr.send_service("test_host", util.get_chrs(send_nsca.nsca.MAX_DESCRIPTION_LENGTH), 0, 'ok')
        assert_raises(ValueError, self.sr.send_service, "test_host", util.get_chrs(send_nsca.nsca.MAX_DESCRIPTION_LENGTH + 1), 0, 'ok')
        # ascii only
        assert_raises(ValueError, self.sr.send_service, "test_host", u"\xff\xf302", 0, 'ok')

    def test_output(self):
        # check plugin output length both for hosts
        self.sr.send_host("test_host", 0, util.get_chrs(send_nsca.nsca.MAX_PLUGINOUTPUT_LENGTH - 1))
        assert_raises(ValueError, self.sr.send_host, "test_host", 0, util.get_chrs(send_nsca.nsca.MAX_PLUGINOUTPUT_LENGTH + 1))
        # and for services
        self.sr.send_service("test_host", "test_service", 0, util.get_chrs(send_nsca.nsca.MAX_PLUGINOUTPUT_LENGTH - 1))
        assert_raises(ValueError, self.sr.send_service, "test_host", "test_service", 0, util.get_chrs(send_nsca.nsca.MAX_PLUGINOUTPUT_LENGTH + 1))

    def test_code(self):
        self.sr.send_host("test_host", 0, "ok")
        # 4 is not a valid nagios status code
        assert_raises(ValueError, self.sr.send_host, "test_host", 4, "ok")

if __name__ == '__main__':
    run()
