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

import array
import functools
import math
import logging
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

from . import nagios

MAX_PASSWORD_LENGTH = 512
MAX_HOSTNAME_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 128
MAX_PLUGINOUTPUT_LENGTH = 512

_TRANSMITTED_IV_SIZE = 128

PACKET_VERSION = 3

log = logging.getLogger("send_nsca")

########  CIPHERS AND CRYPTERS IMPLEMENTATION ########

crypters = {}

class _MetaCrypter(type):
    def __new__(clsarg, *args, **kwargs):
        cls = super(_MetaCrypter, clsarg).__new__(clsarg, *args, **kwargs)
        if cls.crypt_id >= 0:
            crypters[cls.crypt_id] = cls
        return cls

class Crypter(object):
    __metaclass__ = _MetaCrypter

    crypt_id = -1

    def __init__(self, iv, password, random_pool):
        self.iv = iv
        self.password = password
        self.random_pool = random_pool

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
        value_s = map(ord, list(value))
        repeated_iv = map(ord, list(int(math.ceil(float(len(value)) / len(self.iv))) * self.iv))
        repeated_password = map(ord, list(int(math.ceil(float(len(value)) / len(self.password))) * self.password))
        xorer = functools.partial(apply, int.__xor__)
        xor1 = map(xorer, zip(value_s, repeated_iv))
        xor2 = map(xorer, zip(xor1, repeated_password))
        return ''.join(map(chr, xor2))

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
            key += '\0' * (self.key_size - len(self.password))
        if len(self.iv) >= self.CryptoCipher.block_size:
            iv = self.iv[:iv_size]
        else:
            iv += self.random_pool.get_bytes(iv_size - self.iv)
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

########  CRC32 IMPLEMENTATION ########

class CRC32(object):
    """NSCA-specific CRC32 implementation"""

    def __init__(self):
        self.table = array.array('L', [0]*256)
        self.regenerate_table()

    def regenerate_table(self):
        # magic constant from nsca source
        poly = 0xEDB88320
        for i in xrange(256):
            crc = i
            for j in xrange(8, 0, -1):
                if (crc & 1):
                    crc = (crc>>1)^poly
                else:
                    crc = (crc>>1)
            self.table[i] = crc

    def calculate(self, buf):
        crc = 0xFFFFFFFF
        for i,char in enumerate(buf):
            crc = ((crc>>8) & 0xFFFFFFFF) ^ self.table[(crc ^ ord(char)) & 0xFF]
        return crc ^ 0xFFFFFFFF

########  WIRE PROTOCOL IMPLEMENTATION ########

_data_packet_format = '!hxxLLh%ds%ds%dsxx' % (MAX_HOSTNAME_LENGTH, MAX_DESCRIPTION_LENGTH, MAX_PLUGINOUTPUT_LENGTH)
_init_packet_format = '!%dsL' % (_TRANSMITTED_IV_SIZE,)

def get_random_alphanumeric_bytes(bytesz):
    return ''.join(chr(random.randrange(ord('0'), ord('Z'))) for _ in xrange(bytesz))

def _pack_packet(hostname, service, state, output, timestamp, crc):
    """This is more complicated than a call to struct.pack() because we want
    to pad our strings with random bytes, instead of with zeros."""
    requested_length = struct.calcsize(_data_packet_format)
    packet = array.array('c', '\0'*requested_length)
    # first, pack the version, initial crc32, timestamp, and state
    # (collectively:header)
    header_format = '!hxxLLh'
    offset = struct.calcsize(header_format)
    struct.pack_into('!hxxLLh', packet, 0, PACKET_VERSION, 0, timestamp, state)
    # next, pad & pack the hostname
    hostname = hostname + '\0'
    if len(hostname) < MAX_HOSTNAME_LENGTH:
        hostname += get_random_alphanumeric_bytes(MAX_HOSTNAME_LENGTH - len(hostname))
    struct.pack_into('!%ds' % (MAX_HOSTNAME_LENGTH,), packet, offset, hostname)
    offset += struct.calcsize('!%ds' % (MAX_HOSTNAME_LENGTH,))
    # next, pad & pack the service description
    service = service + '\0'
    if len(service) < MAX_DESCRIPTION_LENGTH:
        service += get_random_alphanumeric_bytes(MAX_DESCRIPTION_LENGTH - len(service))
    struct.pack_into('%ds' % (MAX_DESCRIPTION_LENGTH,), packet, offset, service)
    offset += struct.calcsize('!%ds' % (MAX_DESCRIPTION_LENGTH))
    # finally, pad & pack the plugin output
    output = output + '\0'
    if len(output) < MAX_PLUGINOUTPUT_LENGTH:
        output += get_random_alphanumeric_bytes(MAX_PLUGINOUTPUT_LENGTH - len(output))
    struct.pack_into('%ds' % (MAX_PLUGINOUTPUT_LENGTH,), packet, offset, output)
    # compute the CRC32 of what we have so far
    crc_val = crc.calculate(packet)
    struct.pack_into('!L', packet, 4, crc_val)
    return packet.tostring()


########  MAIN CLASS IMPLEMENTATION ########

class ConfigParseError(StandardError):
    def __init__(self, filename, lineno, msg):
        self.filename = filename
        self.lineno = lineno
        self.msg = msg

    def __str__(self):
        return "Configuration parsing error: [%s:%d] %s" % (self.filename, self.lineno, self.msg)

    def __repr__(self):
        return "ConfigParseError(%s, %d, %s)" % (self.filename, self.lineno, self.msg)

class NscaSender(object):
    def __init__(self, remote_host, config_path='/etc/send_nsca.cfg', port=5667, timeout=10, send_to_all=True):
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
        self.CRC32 = CRC32()
        self.Crypter = Crypter
        self._cached_crypters = {}
        self.random_pool = Crypto.Util.randpool.RandomPool()
        if config_path is not None:
            self.parse_config(config_path)

    def parse_config(self, config_path):
        with open(config_path, 'r') as f:
            for line_no, line in enumerate(f):
                if '=' not in line or line.lstrip().startswith('#'):
                    continue
                key, value = [res.strip() for res in line.split('=')]
                try:
                    if key == 'password':
                        if len(value) > MAX_PASSWORD_LENGTH:
                            raise ConfigParseError(config_path, line_no, "Password too long; max %d" % MAX_PASSWORD_LENGTH)
                        self.password = str(value)
                    elif key == 'encryption_method':
                        self.encryption_method_i = int(value)
                        if self.encryption_method_i not in crypters.keys():
                            raise ConfigParseError(config_path, line_no, "Unrecognized uncryption method %d" % (self.encryption_method_i,))
                        self.Crypter = crypters[self.encryption_method_i]
                        if issubclass(self.Crypter, UnsupportedCrypter):
                            raise ConfigParseError(config_path, line_no, "Unsupported cipher type %d (%s)" % (self.Crypter.crypt_id, self.Crypter.__name__))
                    else:
                        raise ConfigParseError(config_path, line_no, "Unrecognized key '%s'" % (key,))
                except ConfigParseError:
                    raise
                except:
                    raise ConfigParseError(config_path, line_no, "Could not parse value '%s' for key '%s'" % (value, key))

    def send_service(self, host, service, state, description):
        if state not in nagios.States.keys():
            raise ValueError("state %r should be one of {%s}" % (state, ','.join(map(str, nagios.States.keys()))))
        self.connect()
        for conn, iv, timestamp in self._conns:
            if conn not in self._cached_crypters:
                self._cached_crypters[conn] = self.Crypter(iv, self.password, self.random_pool)
            crypter = self._cached_crypters[conn]
            packet = _pack_packet(host, service, state, description, timestamp, self.CRC32)
            packet = crypter.encrypt(packet)
            conn.sendall(packet)

    def send_host(self, host, state, description):
        return self.send_service(host, '', state, description)

    def connect(self):
        if self._connected:
            return
        conns = []
        for (family, socktype, proto, canonname, sockaddr) in socket.getaddrinfo(self.remote_host, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM, 0, 0):
            try:
                s = socket.socket(family, socktype, proto)
                s.connect(sockaddr)
                conns.append(s)
                if self.timeout:
                    s.settimeout(self.timeout)
                if not self.send_to_all:
                    break
            except socket.error:
                continue
        if not conns:
            raise socket.error("could not connect to %s:%d" % (self.remote_host, self.port))
        for conn in conns:
            iv, timestamp = self._read_init_packet(conn)
            self._conns.append((conn, iv, timestamp))
        self._connected = True

    def disconnect(self):
        if not self._connected:
            return
        for conn, _, _ in self._conns:
            conn.close()
        self._connected = False

    def _read_init_packet(self, fd):
        init_packet = fd.recv(struct.calcsize(_init_packet_format))
        transmitted_iv, timestamp = struct.unpack(_init_packet_format, init_packet)
        return transmitted_iv, timestamp

    def __del__(self):
        self.disconnect()
