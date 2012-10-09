from testify import assert_equal, assert_in, run

from nsca_test_case import NSCATestCase, ServiceCheckResult, HostCheckResult

import send_nsca


class ConvenienceFunctionTest(NSCATestCase):
    crypto_method = 3

    def assertions(self, status, message):
        checks = self.expect_checks(1)
        assert_equal(len(checks), 1)
        assert_equal(checks[0], ServiceCheckResult(host_name='myhost', service_name='myservice', status=status, output=message))

    def test_send_nsca(self):
        send_nsca.send_nsca(0, 'myhost', 'myservice', 'OK', **self.nsca_sender_args)
        self.assertions(0, 'OK')

    def test_nsca_ok(self):
        send_nsca.nsca_ok('myhost', 'myservice', 'YES!', **self.nsca_sender_args)
        self.assertions(0, 'YES!')

    def test_nsca_warning(self):
        send_nsca.nsca_warning('myhost', 'myservice', 'EEH', **self.nsca_sender_args)
        self.assertions(1, 'EEH')

    def test_nsca_critical(self):
        send_nsca.nsca_critical('myhost', 'myservice', 'oh noes', **self.nsca_sender_args)
        self.assertions(2, 'oh noes')

    def test_nsca_unknown(self):
        send_nsca.nsca_unknown('myhost', 'myservice', 'what', **self.nsca_sender_args)
        self.assertions(3, 'what')


if __name__ == '__main__':
    run()
