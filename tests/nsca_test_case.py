import collections
import os
import os.path
import select
import shutil
import socket
import subprocess
import tempfile
import time

from testify import TestCase, class_setup, class_teardown

from send_nsca.nsca import NscaSender


NSCA_CFG_TEMPLATE = """
password='TestingPassword'
decryption_method=%(crypto_method)d
max_packet_age=30
command_file=%(command_file)s
append_to_file=0
debug=0
server_port=%(port)s
aggregate_writes=0
"""


SEND_NSCA_CFG_TEMPLATE = """
password='TestingPassword'
encryption_method=%(crypto_method)d
"""


def pick_unused_port():
    """
    Grabs a port that is currently unused.

    There is a race condition here in that the returned
    port can be grabbed by any other process.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


HostCheckResult = collections.namedtuple("HostCheckResult", ["host_name", "status", "output"])
ServiceCheckResult = collections.namedtuple("ServiceCheckResult", ["host_name", "service_name", "status", "output"])


class NSCATestCase(TestCase):

    __test__ = False

    crypto_method = 1
    max_read_time = 4

    def _start_nsca(self):
        with open(self.nsca_config_path, 'w') as f:
            f.write(NSCA_CFG_TEMPLATE % {'command_file': self.fifo_name, 'crypto_method': self.crypto_method, 'port': self.server_port})
        with open(self.send_nsca_config_path, 'w') as f:
            f.write(SEND_NSCA_CFG_TEMPLATE % {'crypto_method': self.crypto_method})
        self.nsca_process = subprocess.Popen(["nsca", "-f", "-c", self.nsca_config_path])

    def expect_checks(self, n_checks):
        # This is only complicated because we use the FIFO in non-blocking
        # mode... We really just don't want to end up hanging if the NSCA
        # daemon crashes for some reason
        start_time = time.time()
        poller = select.poll()
        poller.register(self.read_end.fileno(), select.POLLIN | select.POLLHUP | select.POLLERR)
        now = time.time()
        lines = []
        hung_up = False
        while now - start_time < self.max_read_time and not hung_up:
            events = poller.poll(self.max_read_time - (now - start_time))
            now = time.time()
            while True:
                try:
                    l = self.read_end.readline()
                    if not l.rstrip("\n"):
                        break
                    lines.append(self.parse_line(l))
                except IOError, e:
                    break
            if len(lines) == n_checks:
                break
        else:
            raise AssertionError("Read %d lines after %0.2fs, expected %d" % (len(lines), (now - start_time), n_checks))
        return lines

    @property
    def nsca_sender_args(self):
        return {'remote_host': '127.0.0.1', 'port': self.server_port, 'config_path': self.send_nsca_config_path}

    def nsca_sender(self):
        return NscaSender(**self.nsca_sender_args)

    @staticmethod
    def parse_line(l):
        l = l.rstrip("\n")
        time, rest = l.split(" ", 1)
        time = time[1:-1]
        if rest.startswith("PROCESS_HOST_CHECK_RESULT"):
            _, host_name, status, output = rest.split(";")
            return HostCheckResult(host_name=host_name, status=int(status), output=output)
        elif rest.startswith("PROCESS_SERVICE_CHECK_RESULT"):
            _, host_name, service_name, status, output = rest.split(";")
            return ServiceCheckResult(host_name=host_name, service_name=service_name, status=int(status), output=output)
        else:
            raise ValueError("Unexpected result type %s" % rest.split(";")[0])

    @class_setup
    def setup_dir(self):
        self.working_directory = tempfile.mkdtemp()
        self.fifo_name = os.path.join(self.working_directory, 'nsca_fifo')
        self.nsca_config_path = os.path.join(self.working_directory, 'nsca.cfg')
        self.send_nsca_config_path = os.path.join(self.working_directory, 'send_nsca.cfg')
        os.mkfifo(self.fifo_name)
        read_fd = os.open(self.fifo_name, os.O_RDONLY | os.O_NONBLOCK)
        self.read_end = os.fdopen(read_fd)
        self.server_port = pick_unused_port()
        self.nsca_process = None
        self._start_nsca()

    @class_teardown
    def cleanup_dir(self):
        if self.nsca_process:
            try:
                self.nsca_process.terminate()
                if self.nsca_process.poll() is None:
                    time.sleep(0.25)
                    if self.nsca_process.poll() is None:
                        self.nsca_process.kill()
            except:
                pass
        try:
            self.read_end.close()
            shutil.rmtree(self.working_directory)
        except:
            pass
