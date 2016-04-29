from .nsca_test_case import NSCATestCase, ServiceCheckResult, HostCheckResult


class TestBasicFunctionality(NSCATestCase):
    def test_service(self):
        nsca_sender = self.nsca_sender()
        nsca_sender.send_service(b'hello', b'goodbye', 1, b'BAD BAD')
        checks = self.expect_checks(1)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0], ServiceCheckResult(host_name='hello', service_name='goodbye', status=1, output='BAD BAD'))

    def test_host(self):
        nsca_sender = self.nsca_sender()
        nsca_sender.send_host(b'myhost', 3, b'LOOKS ???')
        checks = self.expect_checks(1)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0], HostCheckResult(host_name='myhost', status=3, output='LOOKS ???'))

    def test_both(self):
        nsca_sender = self.nsca_sender()
        nsca_sender.send_host(b'myhost', 3, b'UNKNOWN')
        nsca_sender.send_service(b'myhost', b'myservice', 0, b'OK')
        checks = self.expect_checks(2)
        # ordering is unpredictable
        self.assertIn(HostCheckResult(host_name='myhost', status=3, output='UNKNOWN'), checks)
        self.assertIn(ServiceCheckResult(host_name='myhost', service_name='myservice', status=0, output='OK'), checks)
