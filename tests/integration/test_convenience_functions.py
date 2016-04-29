from .nsca_test_case import NSCATestCase, ServiceCheckResult

import send_nsca


class ConvenienceFunctionTest(NSCATestCase):
    crypto_method = 3

    def assertions(self, status, message):
        checks = self.expect_checks(1)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0], ServiceCheckResult(host_name='myhost', service_name='myservice', status=status, output=message))

    def test_send_nsca(self):
        send_nsca.send_nsca(0, b'myhost', b'myservice', b'OK', **self.nsca_sender_args)
        self.assertions(0, 'OK')

    def test_nsca_ok(self):
        send_nsca.nsca_ok(b'myhost', b'myservice', b'YES!', **self.nsca_sender_args)
        self.assertions(0, 'YES!')

    def test_nsca_warning(self):
        send_nsca.nsca_warning(b'myhost', b'myservice', b'EEH', **self.nsca_sender_args)
        self.assertions(1, 'EEH')

    def test_nsca_critical(self):
        send_nsca.nsca_critical(b'myhost', b'myservice', b'oh noes', **self.nsca_sender_args)
        self.assertions(2, 'oh noes')

    def test_nsca_unknown(self):
        send_nsca.nsca_unknown(b'myhost', b'myservice', b'what', **self.nsca_sender_args)
        self.assertions(3, 'what')
