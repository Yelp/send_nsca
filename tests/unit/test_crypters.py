# -*- coding: utf-8 -*-
import random
import unittest

from send_nsca import nsca


class TestXORCrypter(unittest.TestCase):

    def test_should_handle_case_where_no_password_is_given(self):
        crypter = nsca.XORCrypter('123', '', random.randint)
        result = crypter.encrypt('Test')
        self.assertEqual(result, 'eW@E')
