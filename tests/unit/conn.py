#!/usr/bin/python

import socket

import mock
from testify import TestCase, run, assert_raises, assert_equal, assert_length, setup

import send_nsca


class TestConnectionLogic(TestCase):
    @setup
    def build_sender(self):
        self.sender = send_nsca.NscaSender('test_host')

    def test_no_result_fails(self):
        mock_getaddrinfo = mock.Mock(return_value=[])
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            assert_raises(socket.error, self.sender._sock_connect, 'test_host', 3770)
            assert_raises(socket.error, self.sender.connect)
        mock_getaddrinfo.assert_any_call('test_host', 3770, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, 0)
        mock_getaddrinfo.assert_any_call('test_host', 5667, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, 0)

    def test_sock_connect_one(self):
        mock_getaddrinfo = mock.Mock(return_value=[(2, 1, 6, '', ('10.16.1.20', 5667)), (2, 1, 6, '', ('10.16.1.23', 5667)), (2, 1, 6, '', ('10.16.1.25', 5667))])
        mock_socket = mock.Mock()
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            with mock.patch('socket.socket', mock_socket):
                self.sender._sock_connect('foo', 1, connect_all=False)
        mock_socket.assert_called_once_with(2, 1, 6)
        mock_socket.return_value.connect.assert_called_once_with(('10.16.1.20', 5667))

    def test_sock_connect_timeout(self):
        mock_getaddrinfo = mock.Mock(return_value=[(2, 1, 6, '', ('10.16.1.20', 5667)),])
        mock_socket = mock.Mock()
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            with mock.patch('socket.socket', mock_socket):
                self.sender._sock_connect('foo', 1, timeout=10, connect_all=False)
        assert_equal(mock_socket.call_count, 1)
        mock_socket.return_value.settimeout.assert_called_once_with(10)
        mock_socket.return_value.connect.assert_called_once_with(('10.16.1.20', 5667))

    def test_sock_connect_many(self):
        mock_getaddrinfo = mock.Mock(return_value=[(2, 1, 6, '', ('10.16.1.20', 5667)), (2, 1, 6, '', ('10.16.1.23', 5667)), (2, 1, 6, '', ('10.16.1.25', 5667))])
        mock_socket = mock.Mock()
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            with mock.patch('socket.socket', mock_socket):
                self.sender._sock_connect('foo', 1, connect_all=True)
        assert_equal(mock_socket.call_count, 3)
        mock_socket.return_value.connect.assert_any_call(('10.16.1.20', 5667))
        mock_socket.return_value.connect.assert_any_call(('10.16.1.23', 5667))
        mock_socket.return_value.connect.assert_any_call(('10.16.1.25', 5667))

    def test_connect_flow(self):
        sockets = []
        def add_socket(*args):
            retval = mock.Mock()
            sockets.append(retval)
            return retval
        mock_getaddrinfo = mock.Mock(return_value=[(2, 1, 6, '', ('10.16.1.20', 5667)), (2, 1, 7, '', ('10.0.0.0', 5667))])
        mock_socket = mock.Mock(side_effect=add_socket)
        mock_read_iv = mock.Mock(return_value=(1, 2))
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            with mock.patch('socket.socket', mock_socket):
                with mock.patch.object(self.sender, '_read_init_packet', mock_read_iv):
                    self.sender.connect()
        mock_socket.assert_any_call(2, 1, 6)
        mock_socket.assert_any_call(2, 1, 7)
        assert_length(sockets, 2)
        mock_read_iv.assert_any_call(sockets[0])
        mock_read_iv.assert_any_call(sockets[1])

    def test_disconnect_disconnects(self):
        mock_getaddrinfo = mock.Mock(return_value=[(2, 1, 6, '', ('10.16.1.20', 5667)),])
        mock_socket = mock.Mock()
        mock_read_iv = mock.Mock(return_value=(1, 2))
        with mock.patch('socket.getaddrinfo', mock_getaddrinfo):
            with mock.patch('socket.socket', mock_socket):
                with mock.patch.object(self.sender, '_read_init_packet', mock_read_iv):
                    self.sender.timeout = 1
                    self.sender.connect()
                    assert not mock_socket.return_value.close.called
                    self.sender.disconnect()
        mock_socket.assert_called_once_with(2, 1, 6)
        mock_socket.return_value.settimeout.assert_called_once_with(1)
        mock_socket.return_value.close.assert_called_once_with()

if __name__ == '__main__':
    run()
