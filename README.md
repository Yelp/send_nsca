Overview
----
NSCA is the remote passive acceptance daemon used with many Nagios installs. It
ships with a (C-language) executable called send_nsca for submitting checks.
This is a mostly-clean re-implementation of send_nsca in pure-python. It
supports 10 of the 26 crypto functions used by upstream NSCA, sending to
multiple hosts with one invocation, and timeouts.

Credits/Copyright/License
---
- This software was written by James Brown <jbrown@yelp.com>.
- (C) 2012 Yelp, Inc.
- This software is licensed under the LGPL v2.1

Testing
-----
The unit/integration tests for this package are located in the `tests/` directory.
They require the Testify package (<https://github.com/Yelp/Testify>) and the `nsca`
binary. To run them, simply make sure that your `$PYTHONPATH` is set up correctly
and run `testify -v tests`.

Installing
-----
This software uses setuptools/distutils; you can install it with `sudo python setup.py install`,
and it's easy to write packaging for your favorite OS.

Contributing
----------
It's Github; fork away!

If you really like what you see, maybe you would like to [work here](http://www.yelp.com/careers)?
