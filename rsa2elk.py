#!/usr/bin/env python

########################################################################
# RSA2ELK, by Vincent Maury (license Apache 2.0)
# Converts Netwitness log parser configuration to Logstash configuration
# see https://github.com/blookot/rsa2elk
########################################################################


# This script requires Python 3!
import sys
MIN_PYTHON = (3, 0)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

# handle Ctrl-C to stop
import signal
def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# grab command inputs and initialize global variables
import config
config.init()

# call main func
import convert
convert.convertFile()

print("Execution completed!")
