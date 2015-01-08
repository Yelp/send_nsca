from .nagios import (States, STATE_OK, STATE_WARNING, STATE_CRITICAL, STATE_UNKNOWN)
from .nsca import NscaSender, log

# make pyflakes happy
States = States

version_info = (0, 1, 4)
__version__ = ".".join(map(str, version_info))
__author__ = "James Brown <jbrown@yelp.com>"


def send_nsca(status, host_name, service_name, text_output, remote_host, **kwargs):
    """Helper function to easily send a NSCA message (wraps .nsca.NscaSender)

    Arguments:
        status: Integer describing the status
        host_name: Host name to report as
        service_name: Service to report as
        text_output: Freeform text, should be under 512b
        remote_host: Host name to send to

        All other arguments are passed to the NscaSender constructor
    """
    try:
        n = NscaSender(remote_host=remote_host, **kwargs)
        n.send_service(host_name, service_name, status, text_output)
        n.disconnect()
    except Exception, e:
        log.error("Unable to send NSCA packet to %s for %s:%s (%s)", remote_host, host_name, service_name, str(e))


def nsca_ok(host_name, service_name, text_output, remote_host, **kwargs):
    """Wrapper for the send_nsca() function to easily send an OK

    Arguments:
        host_name: Host name to report as
        service_name: Service to report as
        text_output: Freeform text, should be under 512b
        remote_host: Host name to send to

        All other arguments are passed to the NscaSender constructor
    """
    return send_nsca(
        status=STATE_OK,
        host_name=host_name,
        service_name=service_name,
        text_output=text_output,
        remote_host=remote_host,
        **kwargs
    )


def nsca_warning(host_name, service_name, text_output, remote_host, **kwargs):
    """Wrapper for the send_nsca() function to easily send a WARNING

    Arguments:
        host_name: Host name to report as
        service_name: Service to report as
        text_output: Freeform text, should be under 512b
        remote_host: Host name to send to

        All other arguments are passed to the NscaSender constructor
    """
    return send_nsca(
        status=STATE_WARNING,
        host_name=host_name,
        service_name=service_name,
        text_output=text_output,
        remote_host=remote_host,
        **kwargs
    )


def nsca_critical(host_name, service_name, text_output, remote_host, **kwargs):
    """Wrapper for the send_nsca() function to easily send a CRITICAL

    Arguments:
        host_name: Host name to report as
        service_name: Service to report as
        text_output: Freeform text, should be under 512b
        remote_host: Host name to send to

        All other arguments are passed to the NscaSender constructor
    """
    return send_nsca(
        status=STATE_CRITICAL,
        host_name=host_name,
        service_name=service_name,
        text_output=text_output,
        remote_host=remote_host,
        **kwargs
    )


def nsca_unknown(host_name, service_name, text_output, remote_host, **kwargs):
    """Wrapper for the send_nsca() function to easily send an UNKNONW

    Arguments:
        host_name: Host name to report as
        service_name: Service to report as
        text_output: Freeform text, should be under 1kb
        remote_host: Host name to send to

        All other arguments are passed to the NscaSender constructor
    """
    return send_nsca(
        status=STATE_UNKNOWN,
        host_name=host_name,
        service_name=service_name,
        text_output=text_output,
        remote_host=remote_host,
        **kwargs
    )
