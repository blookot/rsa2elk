#!/usr/bin/env python

########################################################################
# RSA2ELK, by Vincent Maury
# Converts Netwitness log parser configuration to Logstash configuration
# see https://github.com/blookot/rsa2elk
########################################################################

import config
import sys
from funcs import *
from transform import *
from os import system
from os import path
import xml.etree.ElementTree as et



def convertFile():

	# First checking that mandatory files exist
	if path.exists(config.MAPPING_FILE) and path.exists(config.XML_FILE) and path.exists(config.ECAT_FILE) and path.exists(config.INPUT_FILE) and path.exists(config.OUTPUT_FILE):

		print("*** Starting file conversion for " + str(config.XML_FILE))
		# get ecs mapping from file
		with open(config.MAPPING_FILE,"r") as f:
			for l in f:
				splitRes = l.split("||")
				config.ecsField[splitRes[0]] = splitRes[1].replace("\n","")
				config.ecsType[splitRes[0]] = splitRes[2].replace("\n","")

		# get ecat file to enrich categories
		with open(config.ECAT_FILE,"r") as f:
			for l in f:
				if l[:1] != "#":	# avoid line starting with comments
					splitRes = l.split(",",2)
					config.ecat[splitRes[0]] = splitRes[1].replace("\n","")

		# prepare the logstash output file with the input {}
		with open(config.LS_CONF_FILE,"w",newline=None,encoding="utf-8") as lsFile:
			with open(config.INPUT_FILE,"r") as fi:
				lsFile.write(fi.read())

			# write a first filter to change a couple of fields 
			lsFile.write("# Renaming a couple of fields" + CR)
			lsFile.write("filter {" + CR + t(1) + "mutate {" + CR + t(2) + "rename => {" + CR + t(3) + "\"message\" => \"[event][original]\"" + CR)
			lsFile.write(t(3) + "\"host\" => \"[logstash][host]\"" + CR + t(2) + "}" + CR + t(1) + "}" + CR + "}" + CR + CR)

			# start reading the xml doc
			if config.DEBUG:
				print ("** Device: " + config.DEVICE)
				print ("BaseName || Item || Value")
			firstMsg = True
			rsaConfigName = ""; rsaConfigDisplayName = ""; rsaConfigGroup = ""
			# read DEVICEMESSAGES attributes to get config names
			with open(config.XML_FILE, 'r', encoding='iso-8859-1') as xml_file:
				xmlp = et.XMLParser(encoding='iso-8859-1')
				tree = et.parse(xml_file,parser=xmlp)
				root = tree.getroot()
				for nodeKey in root.attrib:
					nodeVal = root.attrib[nodeKey]
					if nodeKey == "name":
						rsaConfigName = nodeVal
					if nodeKey == "displayname":
						rsaConfigDisplayName = nodeVal
					if nodeKey == "group":
						rsaConfigGroup = nodeVal
				# write a first filter to set the device name & group and set the headerfound & messagefound
				lsFile.write("# Setting the device name and group" + CR)
				lsFile.write("filter {" + CR + t(1) + "mutate {" + CR + t(2) + "add_field => {" + CR)
				lsFile.write(t(3) + "\"[observer][product]\" => \"" + rsaConfigName + "\"" + CR + t(3) + "\"[observer][name]\" => \"" + rsaConfigDisplayName + "\"" + CR)
				lsFile.write(t(3) + "\"[observer][type]\" => \"" + rsaConfigGroup + "\"" + CR + t(2) + "}" + CR + t(1) + "}" + CR + "}" + CR)

				# open possible xml custom doc and modify the main xml doc accordingly
				if path.exists(config.XML_CUSTOM_FILE):
					with open(config.XML_CUSTOM_FILE, 'r', encoding='iso-8859-1') as xml_custom_file:
						xmlp = et.XMLParser(encoding='iso-8859-1')
						treeCustom = et.parse(xml_custom_file,parser=xmlp)
						rootCustom = treeCustom.getroot()
						for childCustom in rootCustom:
							if childCustom.tag == "HEADER" or childCustom.tag == "MESSAGE":
								childIndex = 0
								for child in root:
									# replace child when id matches
									if child.get('id1') == childCustom.get('id1') and childCustom.get('insertBefore') is None and childCustom.get('insertAfter') is None:
										if config.DEBUG: print("Replace " + childCustom.get('id1'))
										root.remove(child)
										root.insert(childIndex, childCustom)
										break
									# insert before. note that if there are 2 insertBefore, the second one will be after the first in the resulting config
									elif childCustom.get('insertBefore') == child.get('id1') and childCustom.get('insertBefore') is not None:
										root.insert(childIndex, childCustom)
										if config.DEBUG: print("Insert " + childCustom.get('id1') + " before " + childCustom.get('insertBefore'))
										break
									# insert after. note that if there are 2 insertAfter, the second one will be before the first in the resulting config
									elif childCustom.get('insertAfter') == child.get('id1') and childCustom.get('insertAfter') is not None:
										root.insert(childIndex+1, childCustom)
										if config.DEBUG: print("Insert " + childCustom.get('id1') + " after " + childCustom.get('insertAfter'))
										break
									else:
										childIndex = childIndex + 1

				# now explore the xml tree 
				for child in root:
					nodeName = child.tag
					rsaLine = ""; msgMatch = ""; config.dateFieldMutation = ""; config.dateMatching = ""
					config.messageId = ""; messageId1 = ""; messageId2 = ""; messageParserId = ""; headerId = ""; eventCategory = ""
					config.addedFields = ""; config.parsingError = ""

					# dealing with HEADER nodes
					if nodeName == "HEADER":
						messageParserId = ""
						for nodeKey in child.attrib:
							nodeVal = child.attrib[nodeKey]
							# get the id to add it as a new field
							if nodeKey == "id2":
								headerId = nodeVal
							# get the messageid to compute the id to route to the appropriate message parser
							if nodeKey == "messageid":
								# messageid is a strcat
								messageParserId = convertStrcat(nodeVal)
								if config.DEBUG: print(nodeName + " " + headerId + " || " + nodeKey + " || " + nodeVal)
							if nodeKey == "content":
								rsaLine = nodeVal
								msgMatch = transformHeaderContent(nodeVal)
								if config.DEBUG: print(nodeName + " " + headerId + " || " + nodeKey + " || " + nodeVal)
						# check the msgMatch has been correctly generated
						if config.parsingError != "":
							# content transformation didn't work, just say it
							lsconfFilter = CR + "# HEADER " + headerId + CR + "# line in RSA: " + rsaLine + CR + "# Parsing error: " + config.parsingError
						else:
							# compose the filter section
							lsconfFilter = CR + "# HEADER " + headerId + CR + "# line in RSA: " + rsaLine + CR + "filter {" + CR + t(1) + "if ![logstash][headerfound] {" + CR 
							if config.withDissect:
								lsconfFilter = lsconfFilter + t(2) + "dissect {" + CR + t(3) + "mapping => { " + msgMatch + " }" + CR
							else:
								lsconfFilter = lsconfFilter + t(2) + "grok {" + CR + t(3) + "match => { " + msgMatch + " }" + CR 
							# add a filter id for monitoring purpose
							lsconfFilter = lsconfFilter + t(3) + "id => \"header-" + escapeString(headerId) + "\"" + CR
							# add header id for debugging
							lsconfFilter = lsconfFilter + t(3) + "add_field => {" + CR + t(4) + "\"[rsa][header][id]\" => \"" + escapeString(headerId) + "\"" + CR
							# if no messageParserId, take the "messageid" field from parsing
							if messageParserId == "":
								lsconfFilter = lsconfFilter + t(4) + "\"[rsa][message][id2]\" => \"%{messageid}\"" + CR
							else:
								lsconfFilter = lsconfFilter + t(4) + "\"[rsa][message][id2]\" => \"" + messageParserId + "\"" + CR
							# other added fields from the <@field:value> in header content
							lsconfFilter = lsconfFilter + config.addedFields
							if config.dateFieldMutation != "":
								lsconfFilter = lsconfFilter + t(4) + "\"[logstash][fullDateTimeString]\" => \"" + config.dateFieldMutation + "\"" + CR
							lsconfFilter = lsconfFilter + t(4) + "\"[logstash][headerfound]\" => true" + CR + t(3) + "}" + CR + t(2) + "}" + CR
							if config.dateFieldMutation != "":
								lsconfFilter = lsconfFilter + t(2) + "if [logstash][fullDateTimeString] {" + CR + t(3) + "date { match => [ \"[logstash][fullDateTimeString]\", " + config.dateMatching + " ] }" + CR + t(2) + "}" + CR
							lsconfFilter = lsconfFilter + t(1) + "}" + CR + "}"

						# write the filter block
						lsFile.write(lsconfFilter)

					# dealing with MESSAGE nodes
					if nodeName == "MESSAGE":
						for nodeKey in child.attrib:
							nodeVal = child.attrib[nodeKey]
							# get the id to add it as a new field
							if nodeKey == "id1":
								# by default, the message id is id1, unless there is a msg_id in funcs
								messageId1 = nodeVal
								config.messageId = nodeVal
							if nodeKey == "id2":
								# matching with header on id2
								messageId2 = nodeVal
							# get the event category
							if nodeKey == "eventcategory":
								eventCategory = nodeVal
								config.addedFields = config.addedFields + t(4) + "\"[event][categoryid]\" => \"" + eventCategory + "\"" + CR
								if eventCategory in config.ecat: config.addedFields = config.addedFields + t(4) + "\"[event][category]\" => \"" + config.ecat[eventCategory] + "\"" + CR
							# get transformation functions and compute the corresponding mutates
							if nodeKey == "functions":
								transformFunctions(nodeVal)
								if config.DEBUG: print(nodeName + " " + messageId1 + " || " + nodeKey + " || " + nodeVal)
							if nodeKey == "content":
								rsaLine = nodeVal
								msgMatch = transformMessageContent(nodeVal)
								if config.DEBUG: print(nodeName + " || " + nodeKey + " || " + nodeVal)
						# if first message, add a section bar
						if firstMsg:
							lsFile.write(CR + CR + "###################################" + CR)
							firstMsg = False
						# check the msgMatch has been correctly generated
						if config.parsingError != "":
							# content transformation didn't work, just say it
							lsconfFilter = CR + "# MESSAGE " + messageId1 + CR + "# line in RSA: " + rsaLine + CR + "# Parsing error: " + config.parsingError
						else:
							# compose the filter section
							lsconfFilter = CR + "# MESSAGE " + messageId1 + CR + "# line in RSA: " + rsaLine + CR
							lsconfFilter = lsconfFilter + "filter {" + CR + t(1) + "if ![logstash][messagefound] and [rsa][message][id2] == \"" + escapeString(messageId2) + "\" {" + CR
							if config.withDissect:
								lsconfFilter = lsconfFilter + t(2) + "dissect {" + CR + t(3) + "mapping => { " + msgMatch + " }" + CR
							else:
								lsconfFilter = lsconfFilter + t(2) + "grok {" + CR + t(3) + "match => { " + msgMatch + " }" + CR
							# add a filter id for monitoring purpose
							lsconfFilter = lsconfFilter + t(3) + "id => \"message-" + escapeString(messageId1) + "\"" + CR
							# add new fields
							config.addedFields = config.addedFields + t(4) + "\"[event][id]\" => \"" + escapeString(config.messageId) + "\"" + CR
							config.addedFields = config.addedFields + t(4) + "\"[rsa][message][id1]\" => \"" + escapeString(messageId1) + "\"" + CR
							lsconfFilter = lsconfFilter + t(3) + "add_field => {" + CR + config.addedFields
							# sometimes there is no date filter...
							if config.dateFieldMutation != "":
								lsconfFilter = lsconfFilter + t(4) + "\"[logstash][fullDateTimeString]\" => \"" + config.dateFieldMutation + "\"" + CR
							lsconfFilter = lsconfFilter + t(4) + "\"[logstash][messagefound]\" => true" + CR + t(3) + "}" + CR + t(2) + "}" + CR
							# sometimes there is no date filter...
							if config.dateFieldMutation != "":
								lsconfFilter = lsconfFilter + t(2) + "if [logstash][fullDateTimeString] {" + CR + t(3) + "date { match => [ \"[logstash][fullDateTimeString]\", " + config.dateMatching + " ] }" + CR + t(2) + "}" + CR
							lsconfFilter = lsconfFilter + t(1) + "}" + CR + "}"

						# write the filter block
						lsFile.write(lsconfFilter)

			# visual separator after all messages
			lsFile.write(CR + CR + "###################################" + CR)

			# enrich events with categories
			# lsFile.write(CR + "# Translate event category id in a name (using ecat.ini file from rsa, renamed in ecat.csv)" + CR)
			# lsFile.write()"filter {" + CR + t(1) + "translate {" + CR)
			# lsFile.write(t(2) + "dictionary_path => ""ecat.csv""" + CR)
			# lsFile.write(t(2) + "fallback => ""Other""" + CR)
			# lsFile.write(t(2) + "refresh_interval => 86400" + CR)
			# lsFile.write(t(2) + "refresh_behaviour => ""replace""" + CR)
			# lsFile.write(t(2) + "field => ""event.categoryid""" + CR)
			# lsFile.write(t(2) + "destination => ""event.category""" + CR)
			# lsFile.write(t(1) + "}" + CR + "}" + CR)

			# parse urls
			if config.PARSE_URL:
				lsFile.write(CR)
				with open(config.URL_FILTER_FILE,"r") as fi:
					lsFile.write(fi.read())

			# parse user agents
			if config.PARSE_UA:
				lsFile.write(CR)
				with open(config.UA_FILTER_FILE,"r") as fi:
					lsFile.write(fi.read())

			# enrich IPs with geoip
			if config.ENRICH_GEO:
				lsFile.write(CR)
				with open(config.GEO_FILTER_FILE,"r") as fi:
					lsFile.write(fi.read())

			# enrich IPs with ASN
			if config.ENRICH_ASN:
				lsFile.write(CR)
				with open(config.ASN_FILTER_FILE,"r") as fi:
					lsFile.write(fi.read())

			# add the changes of types (to prepare for ecs mapping and get all other fields as string)
			lsFile.write(CR + "# Convert types of fields" + CR)
			lsFile.write("filter {" + CR + t(1) + "mutate {" + CR + t(2) + "convert => {" + CR)
			for varKey in sorted(config.allFields):
				# jump over the fld* fields
				if varKey != "" and varKey[:3] != "fld" and varKey[:4] != "hfld":
					# if field exists in ECS mapping then rename it, otherwise, leave it as it is
					if varKey in config.ecsField:
						lsFile.write(t(3) + "\"" + varKey + "\" => \"" + config.ecsType[varKey] + "\"" + CR)
					else:
						lsFile.write(t(3) + "\"" + varKey + "\" => \"string\"" + CR)
			lsFile.write(t(2) + "}" + CR + t(1) + "}" + CR + "}" + CR)

			# trim (strip) all text fields
			if config.TRIM_FIELDS:
				first = True
				trimedFields = ""
				for varKey in sorted(config.allFields):
					# jump over the fld* fields
					if varKey != "" and varKey[:3] != "fld" and varKey[:4] != "hfld" and varKey in config.ecsField:
						# if field exists in ECS mapping then check if it's string
						if config.ecsType[varKey] == "string":
							if first:
								trimedFields = trimedFields + "\"" + varKey + "\""
								first = False
							else:
								trimedFields = trimedFields + ", \"" + varKey + "\""
				if trimedFields != "":
					lsFile.write(CR + "# Trim all text fields" + CR)
					lsFile.write("filter {" + CR + t(1) + "mutate {" + CR)
					lsFile.write(t(2) + "strip => [ " + trimedFields + " ]" + CR + t(1) + "}" + CR + "}" + CR)

			# add the changes of names (ecs)
			if config.RENAME_FIELDS:
				lsFile.write(CR + "# Rename fields from RSA log parser meta field names in ECS (Elastic Common Schema) naming" + CR)
				lsFile.write("filter {" + CR + t(1) + "mutate {" + CR + t(2) + "rename => {" + CR)
				for varKey in sorted(config.allFields):
					# jump over the fld* fields
					if varKey != "" and varKey[:3] != "fld" and varKey[:4] != "hfld":
						if varKey in config.ecsField:
							# field name exists in ECS mapping file, so change it
							lsFile.write(t(3) + "\"" + varKey + "\" => \"" + removeDots(config.ecsField[varKey]) + "\"" + CR)
						else:
							# field name doesn't exist, rename it with general category "custom."
							lsFile.write(t(3) + "\"" + varKey + "\" => \"" + removeDots("custom." + varKey) + "\"" + CR)
				lsFile.write(t(2) + "}" + CR + t(1) + "}" + CR + "}" + CR)

			# drop all hfld* and fld* fields
			first = True
			removedFields = ""
			for varKey in sorted(config.allFields):
				# if field exists in ECS mapping then rename it, otherwise, leave it as it is
				if varKey[:4] == "hfld" or varKey[:3] == "fld":
					if first:
						removedFields = removedFields + "\"" + varKey + "\""
						first = False
					else:
						removedFields = removedFields + ", \"" + varKey + "\""
			if removedFields != "":
				lsFile.write(CR + "# Drop all hfld* and fld* fields" + CR)
				lsFile.write("filter {" + CR + t(1) + "mutate {" + CR)
				lsFile.write(t(2) + "remove_field => [ " + removedFields + " ]" + CR + t(1) + "}" + CR + "}" + CR)

			# remove the parsed fields
			if config.REMOVE_PARSED_FIELDS:
				lsFile.write(CR + "# Remove parsed fields" + CR)
				lsFile.write("filter {" + CR + t(1) + "if [logstash][headerfound] and [logstash][messagefound] {" + CR)
				lsFile.write(t(2) + "mutate { remove_field => [ \"[event][original]\", \"message\", \"[logstash][fullDateTimeString]\", \"[rsa][msg][data]\", \"[rsa][msg][id]\", \"[rsa][header][id]\", \"[rsa][message][id1]\", \"[rsa][message][id2]\" ] }" + CR)
				lsFile.write(t(1) + "}" + CR + "}" + CR)

			# add output lines of logstash conf
			with open(config.OUTPUT_FILE,"r") as fi:
				lsFile.write(fi.read())

		print ("Conversion done! See output file: " + str(config.LS_CONF_FILE))

		# test the configuration file
		if config.CHECK_CONF:
			print("Running Logstash to check the configuration...")
			cmd =  "\"" + str(config.LS_EXEC) + "\" -t -f " + str(config.LS_CONF_FILE) + " > " + str(config.LS_STDOUT_FILE) + " 2>&1"
			if config.DEBUG: print("Running Logstash config check: " + cmd)
			system(cmd)
			# read output to check if configuration is ok
			configOk = False; jvmInitError = False; jvmHeapSpace = False
			with open(config.LS_STDOUT_FILE,"r") as fi:
				for l in fi:
					if "Configuration OK" in l:
						configOk = True
					if "Error occurred during initialization of VM" in l:
						jvmInitError = True
					if "Error: Could not create the Java Virtual Machine" in l:
						jvmInitError = True
					if "java.lang.OutOfMemoryError: Java heap space" in l:
						jvmHeapSpace = True
			if configOk:
				print("Logstash config test successful, see test results in " + str(config.LS_STDOUT_FILE))
			elif jvmInitError:
				print("Error in Logstash JVM init, see more details in " + str(config.LS_STDOUT_FILE))
				sys.exit(-2)
			elif jvmHeapSpace:
				print("Error: Java heap space (out of memory), see more details in " + str(config.LS_STDOUT_FILE))
				sys.exit(-2)
			else:
				print("Logstash config test KO, see more details in " + str(config.LS_STDOUT_FILE))
				sys.exit(-3)

	# if files don't exist
	else:
		print("Missing mandatory files! Stopping")
		sys.exit(-1)
