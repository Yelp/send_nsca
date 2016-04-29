#!/usr/bin/python
#
# send_nsca.py: A replacement for the C-based send_nsca, able
# to be run in pure-python. Depends on PyCrypto and Python >= 2.6.
#
# Heavily inspired by (and protocol-compatible with) the original send_nsca,
# written by Ethan Galstad <nagios@nagios.org>, which was available under
# the terms of the GNU General Public License v2.
#
# Not quite feature-complete. The simpler encryption algorithms (null,
# XOR, DES, 3DES, Blowfish, ARC2, and CAST) work, but AES doesn't work
# (the AES that nsca uses isn't compatible with PyCrypto's for reasons
# that I haven't yet determined). Also, ARC4 is broken upstream, and I
# didn't fix it.
#
# Copyright (C) 2012 Yelp, Inc.
# Written by James Brown <jbrown@yelp.com>
#
# This software is available under the terms of the Lesser GNU Public
# License, Version 2.1

from __future__ import with_statement

import array
import binascii
import functools
import logging
import math
import os
import random
import socket
import struct

import Crypto.Cipher.AES
import Crypto.Cipher.ARC2
import Crypto.Cipher.Blowfish
import Crypto.Cipher.DES
import Crypto.Cipher.DES3
import Crypto.Cipher.CAST
import Crypto.Util.randpool
import six

from . import nagios

MAX_PASSWORD_LENGTH = 512
MAX_HOSTNAME_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 128
MAX_PLUGINOUTPUT_LENGTH = 512

_TRANSMITTED_IV_SIZE = 128

PACKET_VERSION = 3

DEFAULT_PORT = 5667

log = logging.getLogger("send_nsca")

########  CIPHERS AND CRYPTERS IMPLEMENTATION ########

crypters = {}


class _MetaCrypter(type):
    def __new__(clsarg, *args, **kwargs):
        cls = super(_MetaCrypter, clsarg).__new__(clsarg, *args, **kwargs)
        if cls.crypt_id >= 0:
            crypters[cls.crypt_id] = cls
        return cls


class Crypter(six.with_metaclass(_MetaCrypter, object)):
    crypt_id = -1

    def __init__(self, iv, password, random_generator):
        self.iv = iv
        self.password = password
        self.random_generator = random_generator

    def encrypt(self, value):
        raise NotImplementedError("Implement me!")


class UnsupportedCrypter(Crypter):
    crypt_id = -1


class NullCrypter(Crypter):
    crypt_id = 0

    def encrypt(self, value):
        return value


class XORCrypter(Crypter):
    crypt_id = 1

    def encrypt(self, value):
        value_s = six.iterbytes(value)
        repeated_iv = six.iterbytes(list(int(math.ceil(float(len(value)) / len(self.iv))) * self.iv))
        repeated_password = six.iterbytes(list(int(math.ceil(float(len(value)) / len(self.password))) * self.password))
        xor1 = [a ^ b for a, b in zip(value_s, repeated_iv)]
        xor2 = [a ^ b for a, b in zip(xor1, repeated_password)]
        return b''.join(map(six.int2byte, xor2))


class CryptoCrypter(Crypter):
    crypt_id = -1
    # override this
    CryptoCipher = Crypto.Cipher.DES
    # usually override this
    key_size = 7
    # rarely override this
    iv_size = None

    def __init__(self, *args):
        super(CryptoCrypter, self).__init__(*args)
        key = self.password
        iv = self.iv
        if self.iv_size is not None:
            iv_size = self.iv_size
        else:
            iv_size = self.CryptoCipher.block_size
        if len(self.password) >= self.key_size:
            key = self.password[:self.key_size]
        else:
            key += b'\0' * (self.key_size - len(self.password))
        if len(self.iv) >= self.CryptoCipher.block_size:
            iv = self.iv[:iv_size]
        else:
            iv += self.random_generator(iv_size - self.iv)
        self.crypter = self.CryptoCipher.new(key, self.CryptoCipher.MODE_CFB, iv)

    def encrypt(self, value):
        return self.crypter.encrypt(value)


class DESCrypter(CryptoCrypter):
    crypt_id = 2
    CryptoCipher = Crypto.Cipher.DES
    key_size = 8


class DES3Crypter(CryptoCrypter):
    crypt_id = 3
    CryptoCipher = Crypto.Cipher.DES3
    key_size = 24


class CAST128Crypter(CryptoCrypter):
    crypt_id = 4
    CryptoCipher = Crypto.Cipher.CAST
    key_size = 16


class CAST256Crypter(UnsupportedCrypter):
    crypt_id = 5


class XTEACrypter(UnsupportedCrypter):
    crypt_id = 6


class ThreeWayCrypter(UnsupportedCrypter):
    crypt_id = 7


class BlowFishCrypter(CryptoCrypter):
    crypt_id = 8
    CryptoCipher = Crypto.Cipher.Blowfish
    key_size = 56


class TwoFishCrypter(UnsupportedCrypter):
    crypt_id = 9


class Loki97Crypter(UnsupportedCrypter):
    crypt_id = 10


class RC2Crypter(CryptoCrypter):
    crypt_id = 11
    CryptoCipher = Crypto.Cipher.ARC2
    key_size = 128


class RC4Crypter(UnsupportedCrypter):
    crypt_id = 12
    # We actually can support this one, but the server-side nsca is broken
    # for it (since server-side always runs in CFB mode, even though RC4
    # doesn't have a CFB mode)


class RC6Crypter(UnsupportedCrypter):
    crypt_id = 13


class AES128Crypter(CryptoCrypter):
    crypt_id = 14
    CryptoCipher = Crypto.Cipher.AES
    key_size = 16


class AES192Crypter(CryptoCrypter):
    crypt_id = 15
    CryptoCipher = Crypto.Cipher.AES
    key_size = 24


class AES256Crypter(CryptoCrypter):
    crypt_id = 16
    CryptoCipher = Crypto.Cipher.AES
    key_size = 32

########  WIRE PROTOCOL IMPLEMENTATION ########

_data_packet_format = '!hxxLLh%ds%ds%dsxx' % (MAX_HOSTNAME_LENGTH, MAX_DESCRIPTION_LENGTH, MAX_PLUGINOUTPUT_LENGTH)
_init_packet_format = '!%dsL' % (_TRANSMITTED_IV_SIZE,)


def get_random_alphanumeric_bytes(bytesz):
    return ''.join(chr(random.randrange(ord('0'), ord('Z'))) for _ in range(bytesz)).encode('US-ASCII')


def _pack_packet(hostname, service, state, output, timestamp):
    """This is more complicated than a call to struct.pack() because we want
    to pad our strings with random bytes, instead of with zeros."""
    requested_length = struct.calcsize(_data_packet_format)
    packet = array.array('B', b'\0' * requested_length)
    # first, pack the version, initial crc32, timestamp, and state
    # (collectively:header)
    header_format = '!hxxLLh'
    offset = struct.calcsize(header_format)
    struct.pack_into('!hxxLLh', packet, 0, PACKET_VERSION, 0, timestamp, state)
    # next, pad & pack the hostname
    hostname = hostname + b'\0'
    if len(hostname) < MAX_HOSTNAME_LENGTH:
        hostname += get_random_alphanumeric_bytes(MAX_HOSTNAME_LENGTH - len(hostname))
    struct.pack_into('!%ds' % (MAX_HOSTNAME_LENGTH,), packet, offset, hostname)
    offset += struct.calcsize('!%ds' % (MAX_HOSTNAME_LENGTH,))
    # next, pad & pack the service description
    service = service + b'\0'
    if len(service) < MAX_DESCRIPTION_LENGTH:
        service += get_random_alphanumeric_bytes(MAX_DESCRIPTION_LENGTH - len(service))
    struct.pack_into('%ds' % (MAX_DESCRIPTION_LENGTH,), packet, offset, service)
    offset += struct.calcsize('!%ds' % (MAX_DESCRIPTION_LENGTH))
    # finally, pad & pack the plugin output
    output = output + b'\0'
    if len(output) < MAX_PLUGINOUTPUT_LENGTH:
        output += get_random_alphanumeric_bytes(MAX_PLUGINOUTPUT_LENGTH - len(output))
    struct.pack_into('%ds' % (MAX_PLUGINOUTPUT_LENGTH,), packet, offset, output)
    # compute the CRC32 of what we have so far
    crc_val = binascii.crc32(packet) & 0xffffffff
    struct.pack_into('!L', packet, 4, crc_val)
    return packet.tostring()


########  MAIN CLASS IMPLEMENTATION ########

class ConfigParseError(Exception):
    def __init__(self, filename, lineno, msg):
        self.filename = filename
        self.lineno = lineno
        self.msg = msg

    def __str__(self):
        return "Configuration parsing error: [%s:%d] %s" % (self.filename, self.lineno, self.msg)

    def __repr__(self):
        return "ConfigParseError(%s, %d, %s)" % (self.filename, self.lineno, self.msg)


class NscaSender(object):
    def __init__(self, remote_host, config_path='/etc/send_nsca.cfg', port=DEFAULT_PORT, timeout=10, send_to_all=True):
        """Constructor

        Arguments:
            config_path: path to the nsca config file. Usually /etc/send_nsca.cfg. None to disable.
            remote_host: host to send to
            send_to_all: If true, will repeat your message to *all* hosts that match the lookup for remote_host
        """
        self.port = port
        self.timeout = timeout
        self.password = ''
        self.encryption_method_i = 0
        self.remote_host = remote_host
        self.send_to_all = send_to_all
        self._conns = []
        self._connected = False
        self.Crypter = Crypter
        self._cached_crypters = {}
        self.random_generator = os.urandom
        if config_path is not None:
            with open(config_path, 'rb') as f:
                self.parse_config(f, config_path=config_path)

    def parse_config(self, config_file_object, config_path=""):
        config_file_object.seek(0)
        for line_no, line in enumerate(config_file_object):
            if b'=' not in line or line.lstrip().startswith(b'#'):
                continue
            key, value = [res.strip() for res in line.split(b'=')]
            try:
                if key == b'password':
                    if len(value) > MAX_PASSWORD_LENGTH:
                        raise ConfigParseError(config_path, line_no, "Password too long; max %d" % MAX_PASSWORD_LENGTH)
                    assert isinstance(value, bytes), value
                    self.password = value
                elif key == b'encryption_method':
                    self.encryption_method_i = int(value)
                    if self.encryption_method_i not in crypters.keys():
                        raise ConfigParseError(
                            config_path,
                            line_no,
                            "Unrecognized uncryption method %d" % (self.encryption_method_i,)
                        )
                    self.Crypter = crypters[self.encryption_method_i]
                    if issubclass(self.Crypter, UnsupportedCrypter):
                        raise ConfigParseError(
                            config_path,
                            line_no,
                            "Unsupported cipher type %d (%s)" % (self.Crypter.crypt_id, self.Crypter.__name__)
                        )
                else:
                    raise ConfigParseError(config_path, line_no, "Unrecognized key '%s'" % (key,))
            except ConfigParseError:
                raise
            except:
                raise ConfigParseError(config_path, line_no, "Could not parse value '%s' for key '%s'" % (value, key))

    def _check_alert(self, host=None, service=None, state=None, description=None):
        if state not in nagios.States.keys():
            raise ValueError("state %r should be one of {%s}" % (state, ','.join(map(str, nagios.States.keys()))))
        if not isinstance(host, bytes):
            raise ValueError("host %r must be a non-unicode string" % (host))
        if len(host) > MAX_HOSTNAME_LENGTH:
            raise ValueError("host %r too long (max length %d)" % (host, MAX_HOSTNAME_LENGTH))
        if not isinstance(description, bytes):
            raise ValueError("plugin output %r must be a non-unicode string" % (description))
        if len(description) > MAX_PLUGINOUTPUT_LENGTH:
            raise ValueError("plugin output %r too long (max length %d)" % (description, MAX_PLUGINOUTPUT_LENGTH))
        if service is not None:
            if not isinstance(service, bytes):
                raise ValueError("service %r must be a non-unicode string" % (service))
            if len(service) > MAX_DESCRIPTION_LENGTH:
                raise ValueError("service %r too long (max length %d)" % (service, MAX_DESCRIPTION_LENGTH))

    def send_service(self, host, service, state, description):
        self._check_alert(host=host, service=service, state=state, description=description)
        self.connect()
        for conn, iv, timestamp in self._conns:
            if conn not in self._cached_crypters:
                self._cached_crypters[conn] = self.Crypter(iv, self.password, self.random_generator)
            crypter = self._cached_crypters[conn]
            packet = _pack_packet(host, service, state, description, timestamp)
            packet = crypter.encrypt(packet)
            conn.sendall(packet)

    def send_host(self, host, state, description):
        return self.send_service(host, b'', state, description)

    def _sock_connect(self, host, port, timeout=None, connect_all=True):
        conns = []
        for (family, socktype, proto, canonname, sockaddr) in socket.getaddrinfo(
                host, port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, 0):
            try:
                s = socket.socket(family, socktype, proto)
                s.connect(sockaddr)
                conns.append(s)
                if timeout is not None:
                    s.settimeout(timeout)
                if not connect_all:
                    break
            except socket.error:
                continue
        if not conns:
            raise socket.error("could not connect to %s:%d" % (self.remote_host, self.port))
        return conns

    def _handshake_all(self, conns):
        handshakes = []
        for conn in conns:
            iv, timestamp = self._read_init_packet(conn)
            handshakes.append((conn, iv, timestamp))
        return handshakes

    def connect(self):
        if self._connected:
            return
        conns = self._sock_connect(self.remote_host, self.port, self.timeout, connect_all=self.send_to_all)
        self._conns.extend(self._handshake_all(conns))
        self._connected = True

    def disconnect(self):
        if not self._connected:
            return
        for conn, _, _ in self._conns:
            conn.close()
        self._conns = []
        self._connected = False

    def _read_init_packet(self, fd):
        init_packet = fd.recv(struct.calcsize(_init_packet_format))
        transmitted_iv, timestamp = struct.unpack(_init_packet_format, init_packet)
        return transmitted_iv, timestamp

    def __del__(self):
        self.disconnect()
