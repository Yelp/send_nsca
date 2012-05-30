from testify import assert_equal, run

from nsca_test_case import NSCATestCase, ServiceCheckResult


class TestCrypter(NSCATestCase):
    __test__ = False

    crypto_method = 0

    def test_basic(self):
        nsca_sender = self.nsca_sender()
        nsca_sender.send_service('hello', 'goodbye', 0, 'SUCCESS')
        nsca_sender.send_service('hello', 'goodbye', 1, 'WARN')
        nsca_sender.send_service('hello', 'goodbye', 2, 'CRITICAL')
        checks = self.expect_checks(3)
        assert_equal(len(checks), 3)
        assert_equal(checks[0], ServiceCheckResult(host_name='hello', service_name='goodbye', status=0, output='SUCCESS'))
        assert_equal(checks[1], ServiceCheckResult(host_name='hello', service_name='goodbye', status=1, output='WARN'))
        assert_equal(checks[2], ServiceCheckResult(host_name='hello', service_name='goodbye', status=2, output='CRITICAL'))


class TestNullCrypter(TestCrypter):
    crypto_method = 0


class TestXorCrypter(TestCrypter):
    crypto_method = 1


class TestDESCrypter(TestCrypter):
    crypto_method = 2


class TestDES3Crypter(TestCrypter):
    crypto_method = 3


class TestCAST128Crypter(TestCrypter):
    crypto_method = 4


class TestBlowFishCrypter(TestCrypter):
    crypto_method = 8


if __name__ == '__main__':
    run()
