import socket

import mock
from testify import TestCase, run, assert_raises, assert_equal, assert_length, setup

import send_nsca
from send_nsca.nsca import DEFAULT_PORT

class TestConnectionLogic(TestCase):
    host_one = '10.0.0.1'
    addrinfo_one = (socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP, '', ('10.0.0.1', DEFAULT_PORT))
    host_two = '10.0.0.2'
    addrinfo_two = (socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP, '', ('10.0.0.2', DEFAULT_PORT))
    host_three = '10.0.0.3'
    addrinfo_three = (socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP, '', ('10.0.0.3', DEFAULT_PORT))
    host_four = '10.0.0.4'
    addrinfo_four = (socket.AF_INET, socket.SOCK_STREAM, socket.SOL_UDP, '', ('10.0.0.4', DEFAULT_PORT))
    sigil_one = object()
    sigil_two = object()

    @setup
    def build_sender(self):
        self.sender = send_nsca.NscaSender('test_host', config_path=None)

    def test_no_result_fails(self):
        mock_getaddrinfo = mock.Mock(return_value=[])
        # use a non-standard port so we can ensure that the calling worked
        # right
        test_port = 3770
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            assert_raises(socket.error, self.sender._sock_connect, 'test_host', test_port)
            assert_raises(socket.error, self.sender.connect)
        mock_getaddrinfo.assert_any_call('test_host', test_port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, 0)
        mock_getaddrinfo.assert_any_call('test_host', DEFAULT_PORT, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, 0)

    def test_sock_connect_one(self):
        mock_getaddrinfo = mock.Mock(return_value=[self.addrinfo_one, self.addrinfo_two, self.addrinfo_three])
        mock_socket = mock.Mock()
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            with mock.patch('socket.socket', mock_socket):
                self.sender._sock_connect('foo', 1, connect_all=False)
        mock_socket.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP)
        mock_socket.return_value.connect.assert_called_once_with((self.host_one, DEFAULT_PORT))

    def test_sock_connect_timeout(self):
        mock_getaddrinfo = mock.Mock(return_value=[self.addrinfo_one])
        mock_socket = mock.Mock()
        test_timeout = 1024
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            with mock.patch('socket.socket', mock_socket):
                self.sender._sock_connect('foo', 1, timeout=test_timeout, connect_all=False)
        assert_equal(mock_socket.call_count, 1)
        mock_socket.return_value.settimeout.assert_called_once_with(test_timeout)
        mock_socket.return_value.connect.assert_called_once_with((self.host_one, DEFAULT_PORT))

    def test_sock_connect_many(self):
        mock_getaddrinfo = mock.Mock(return_value=[self.addrinfo_one, self.addrinfo_two, self.addrinfo_three])
        mock_socket = mock.Mock()
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            with mock.patch('socket.socket', mock_socket):
                self.sender._sock_connect('foo', 1, connect_all=True)
        assert_equal(mock_socket.call_count, 3)
        mock_socket.return_value.connect.assert_any_call((self.host_one, DEFAULT_PORT))
        mock_socket.return_value.connect.assert_any_call((self.host_two, DEFAULT_PORT))
        mock_socket.return_value.connect.assert_any_call((self.host_three, DEFAULT_PORT))

    def test_connect_flow(self):
        sockets = []
        def add_socket(*args):
            retval = mock.Mock()
            sockets.append(retval)
            return retval
        mock_getaddrinfo = mock.Mock(return_value=[self.addrinfo_one, self.addrinfo_four])
        mock_socket = mock.Mock(side_effect=add_socket)
        mock_read_iv = mock.Mock(return_value=(self.sigil_one, self.sigil_two))
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            with mock.patch('socket.socket', mock_socket):
                with mock.patch.object(self.sender, '_read_init_packet', mock_read_iv):
                    self.sender.connect()
        mock_socket.assert_any_call(socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP)
        mock_socket.assert_any_call(socket.AF_INET, socket.SOCK_STREAM, socket.SOL_UDP)
        assert_length(sockets, 2)
        mock_read_iv.assert_any_call(sockets[0])
        mock_read_iv.assert_any_call(sockets[1])

    def test_disconnect_disconnects(self):
        mock_getaddrinfo = mock.Mock(return_value=[self.addrinfo_one])
        mock_socket = mock.Mock()
        mock_read_iv = mock.Mock(return_value=(self.sigil_one, self.sigil_two))
        test_timeout = 1024
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            with mock.patch('socket.socket', mock_socket):
                with mock.patch.object(self.sender, '_read_init_packet', mock_read_iv):
                    self.sender.timeout = test_timeout
                    self.sender.connect()
                    assert not mock_socket.return_value.close.called
                    self.sender.disconnect()
        mock_socket.assert_any_call(socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP)
        mock_socket.return_value.settimeout.assert_called_once_with(test_timeout)
        mock_socket.return_value.close.assert_called_once_with()

if __name__ == '__main__':
    run()
