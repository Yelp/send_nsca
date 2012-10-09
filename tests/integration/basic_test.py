from testify import assert_equal, assert_in, run

from nsca_test_case import NSCATestCase, ServiceCheckResult, HostCheckResult


class TestBasicFunctionality(NSCATestCase):
    def test_service(self):
        nsca_sender = self.nsca_sender()
        nsca_sender.send_service('hello', 'goodbye', 1, 'BAD BAD')
        checks = self.expect_checks(1)
        assert_equal(len(checks), 1)
        assert_equal(checks[0], ServiceCheckResult(host_name='hello', service_name='goodbye', status=1, output='BAD BAD'))

    def test_host(self):
        nsca_sender = self.nsca_sender()
        nsca_sender.send_host('myhost', 3, 'LOOKS ???')
        checks = self.expect_checks(1)
        assert_equal(len(checks), 1)
        assert_equal(checks[0], HostCheckResult(host_name='myhost', status=3, output='LOOKS ???'))

    def test_both(self):
        nsca_sender = self.nsca_sender()
        nsca_sender.send_host('myhost', 3, 'UNKNOWN')
        nsca_sender.send_service('myhost', 'myservice', 0, 'OK')
        checks = self.expect_checks(2)
        # ordering is unpredictable
        assert_in(HostCheckResult(host_name='myhost', status=3, output='UNKNOWN'), checks)
        assert_in(ServiceCheckResult(host_name='myhost', service_name='myservice', status=0, output='OK'), checks)


if __name__ == '__main__':
    run()
