import mock
from unittest2 import TestCase

import send_nsca

from .. import util


class TestLimits(TestCase):
    def setUp(self):
        self.sr = send_nsca.nsca.NscaSender(remote_host='test', config_path=None)
        p = mock.patch.object(self.sr, 'connect')
        p.start()
        self.addCleanup(p.stop)

    def test_hostname(self):
        # check that we can send valid packets
        self.sr.send_host(util.get_chrs(send_nsca.nsca.MAX_HOSTNAME_LENGTH - 1), 0, b'ok')
        self.sr.send_host(util.get_chrs(send_nsca.nsca.MAX_HOSTNAME_LENGTH), 0, b'ok')
        # check that we cannot send invalid packets
        self.assertRaises(ValueError, self.sr.send_host, util.get_chrs(send_nsca.nsca.MAX_HOSTNAME_LENGTH + 1), 0, b'ok')
        # ascii only
        self.assertRaises(ValueError, self.sr.send_host, u"\xff\xf302", 0, b'ok')

    def test_service_name(self):
        self.sr.send_service(b"test_host", util.get_chrs(send_nsca.nsca.MAX_DESCRIPTION_LENGTH - 1), 0, b'ok')
        self.sr.send_service(b"test_host", util.get_chrs(send_nsca.nsca.MAX_DESCRIPTION_LENGTH), 0, b'ok')
        self.assertRaises(ValueError, self.sr.send_service, b"test_host", util.get_chrs(send_nsca.nsca.MAX_DESCRIPTION_LENGTH + 1), 0, b'ok')
        # ascii only
        self.assertRaises(ValueError, self.sr.send_service, b"test_host", u"\xff\xf302", 0, b'ok')

    def test_output(self):
        # check plugin output length both for hosts
        self.sr.send_host(b"test_host", 0, util.get_chrs(send_nsca.nsca.MAX_PLUGINOUTPUT_LENGTH - 1))
        self.assertRaises(ValueError, self.sr.send_host, b"test_host", 0, util.get_chrs(send_nsca.nsca.MAX_PLUGINOUTPUT_LENGTH + 1))
        # and for services
        self.sr.send_service(b"test_host", b"test_service", 0, util.get_chrs(send_nsca.nsca.MAX_PLUGINOUTPUT_LENGTH - 1))
        self.assertRaises(ValueError, self.sr.send_service, b"test_host", b"test_service", 0, util.get_chrs(send_nsca.nsca.MAX_PLUGINOUTPUT_LENGTH + 1))

    def test_code(self):
        self.sr.send_host(b"test_host", 0, b"ok")
        # 4 is not a valid nagios status code
        self.assertRaises(ValueError, self.sr.send_host, b"test_host", 4, b"ok")
