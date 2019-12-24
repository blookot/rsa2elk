#!/usr/bin/env python

########################################################################
# RSA2ELK, by Vincent Maury
# Converts Netwitness log parser configuration to Logstash configuration
# see https://github.com/blookot/rsa2elk
########################################################################

import sys
import signal
import os
from pathlib import Path
import argparse
import urllib.request


# variables
DEBUG = False
CHECK_CONF = False
CURRENT_DIR = os.getcwd()		# directory of the script
# input 
DEVICE = ""; DEVICE_FNAME = ""; DEVICE_PATH = ""; DEVICE_EXTENSION = ""
XML_FILE = ""
# output
LS_CONF_FILE = ""; LS_OUTPUT_PATH = ""; LS_OUTPUT_FNAME = ""
LS_EXEC = Path("C:/Users/maury/Documents/tech/logstash-7.5.0/bin/logstash.bat")
LS_STDOUT_FILE = Path(CURRENT_DIR) / "output-logstash-configtest.txt"
# other files
MAPPING_FILE = Path(CURRENT_DIR) / "rsa2ecs.txt"
ECAT_FILE = Path(CURRENT_DIR) / "ecat.ini"
INPUT_FILE = Path(CURRENT_DIR) / "input.conf"
OUTPUT_FILE = Path(CURRENT_DIR) / "output.conf"
URL_FILTER_FILE = Path(CURRENT_DIR) / "filter-url.conf"
# converter tuning
FULL_GROK_ANCHORS = False
SINGLE_SPACE = False
ADD_STOP_ANCHORS = ""

addedFields = ""
ecsField = {}
ecsType = {}
ecat = {}
allFields = set() 


def init():
	# updating global variables
	global DEBUG 
	global CHECK_CONF
	global CURRENT_DIR
	global LS_EXEC
	global DEVICE; global DEVICE_FNAME; global DEVICE_PATH; global DEVICE_EXTENSION 
	global XML_FILE
	global LS_CONF_FILE; global LS_OUTPUT_PATH; global LS_OUTPUT_FNAME
	global FULL_GROK_ANCHORS ; global SINGLE_SPACE; global ADD_STOP_ANCHORS

	# Getting arguments
	parser = argparse.ArgumentParser(description='Converts Netwitness log parser configuration to Logstash configuration.\n' + \
		'Customize input.conf & output.conf to fit your logstash inputs & outputs.\n' + \
		'Author: Vincent Maury (https://github.com/blookot/rsa2elk)\n'+ \
		'License: Apache 2.0')
	parser.add_argument('-i', '--input-file', action='store', default='', help='Absolute path to RSA XML file')
	parser.add_argument('-u', '--url', action='store', default='', help='url of RSA XML file')
	parser.add_argument('-o', '--output-file', action='store', default='', help='Absolute path to Logstash .conf file (default: logstash-[device].conf)')
	parser.add_argument('-c', '--check-config', action='store_true', default=False, help='Check the generated configuration with `logstash -f` (default: false)')
	parser.add_argument('-l', '--logstash-path', action='store', default='', help='Absolute path to logstash')
	parser.add_argument('-f', '--full-grok-anchors', action='store_true', default=False, help='Add begining (^) and end ($) anchors in grok (default: false)')
	parser.add_argument('-a', '--add-stop-anchors', action='store', default='', help='Add hard stop anchors in grok (as a serie of plain characters, only escaping " and \\) to ignore in-between chars, for example \\"()[] (default: "")')
	parser.add_argument('-s', '--single-space-match', action='store_true', default=False, help='Only match 1 space if there is 1 space in the RSA parser (default: false, ie match 1-N spaces aka [\\s]+)')
	parser.add_argument('-d', '--debug', action='store_true', default=False, help='Debug mode, more verbose (default: false)')
	results = parser.parse_args()
	# capture inputs
	DEBUG = results.debug
	if results.input_file == '' and results.url == '':
		# take a sample configuration: zscaler
		print("No input selected, using online https://raw.githubusercontent.com/netwitness/nw-logparsers/master/devices/zscalernss/zscalernssmsg.xml file (see --help for more info)")
		if DEBUG: print("Beginning file download")
		try:
			url = "https://raw.githubusercontent.com/netwitness/nw-logparsers/master/devices/zscalernss/zscalernssmsg.xml"
			DEVICE_FNAME = "zscalernssmsg.xml"
			XML_FILE = Path(CURRENT_DIR) / DEVICE_FNAME
			urllib.request.urlretrieve(url, XML_FILE)
			(DEVICE, DEVICE_EXTENSION) = os.path.splitext(DEVICE_FNAME)
			print("Using downloaded file " + DEVICE_FNAME + " in local directory")
		except Exception as e:
			print("Couldn't download file, aborting")
			print('Error: '+str(e))
			sys.exit(0)
	if results.input_file != '':
		XML_FILE = Path(results.input_file)
		(DEVICE_PATH, DEVICE_FNAME) = os.path.split(XML_FILE)
		# if same folder, just add it
		if DEVICE_PATH == "":
			XML_FILE = Path(CURRENT_DIR) / DEVICE_FNAME
		(DEVICE, DEVICE_EXTENSION) = os.path.splitext(DEVICE_FNAME)
	# download file if given url
	if results.url != '':
		if DEBUG: print("Beginning file download")
		try:
			url = results.url
			DEVICE_FNAME = url.rsplit('/', 1)[1]
			XML_FILE = Path(CURRENT_DIR) / DEVICE_FNAME
			urllib.request.urlretrieve(url, XML_FILE)
			(DEVICE, DEVICE_EXTENSION) = os.path.splitext(DEVICE_FNAME)
			print("Using downloaded file " + DEVICE_FNAME + " in local directory")
		except Exception as e:
			print("Couldn't download file, aborting")
			print('Error: '+str(e))
			sys.exit(0)
	if results.output_file != '':
		LS_CONF_FILE = Path(results.output_file)
		(LS_OUTPUT_PATH, LS_OUTPUT_FNAME) = os.path.split(LS_CONF_FILE)
		# if same folder, just add it
		if LS_OUTPUT_PATH == "":
			LS_CONF_FILE = Path(CURRENT_DIR) / LS_OUTPUT_FNAME
	else:
		LS_CONF_FILE = Path(CURRENT_DIR) / ("logstash-" + DEVICE + ".conf")
	CHECK_CONF = results.check_config
	FULL_GROK_ANCHORS = results.full_grok_anchors
	SINGLE_SPACE = results.single_space_match
	ADD_STOP_ANCHORS = results.add_stop_anchors
	if results.logstash_path != '':
		LS_EXEC = Path(results.logstash_path)
