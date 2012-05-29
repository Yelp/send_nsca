WHAT
----
NSCA is the remote passive acceptance daemon used with many Nagios installs. It
ships with a (C-language) executable called send_nsca for submitting checks.
This is a mostly-clean re-implementation of send_nsca in pure-python. It
supports 10 of the 26 crypto functions used by upstream NSCA, sending to
multiple hosts in parallel, and timeouts.

WHO
---
This software was written by James Brown <jbrown@yelp.com>.

WHEN
----
(C) 2012 Yelp, Inc.

WHY
---
send_nsca is bloody scary

HOW
---
This software is licensed under the LGPL v2.1
