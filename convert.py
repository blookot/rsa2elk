#!/usr/bin/env python

########################################################################
# RSA2ELK, by Vincent Maury
# Converts Netwitness log parser configuration to Logstash configuration
# see https://github.com/blookot/rsa2elk
########################################################################

import config
from funcs import *
from transform import *
import os
import xml.etree.ElementTree as et



def convertFile():

	print("Starting file conversion...")
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
	with open(config.LS_CONF_FILE,"w",newline=None) as lsFile:
		with open(config.INPUT_FILE,"r") as fi:
			lsFile.write(fi.read())

		# write a first filter to set the device name
		lsFile.write("filter {" + CR + t(1) + "mutate {" + CR + t(2) + "rename => { \"message\" => \"[event][original]\" }" + CR + t(2) + "add_field => { \"[observer][name]\" => \"" + config.DEVICE + "\" }" + CR + t(1) + "}" + CR + "}" + CR)

		# start reading the xml doc
		if config.DEBUG:
			print ("** Device: " + config.DEVICE)
			print ("BaseName || Item || Value")
		tree = et.parse(config.XML_FILE)
		root = tree.getroot()
		for child in root:
			# print (child.tag, child.attrib)
			nodeName = child.tag
			rsaLine = ""; grok = ""; dateFields = ""; dateFieldMutation = ""; dateMatching = ""
			messageId = ""; messageParserId = ""; headerId = ""; eventCategory = ""
			config.addedFields = ""; dateFields = ""
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
						grok = transformHeaderContent(nodeVal)
						if config.DEBUG: print(nodeName + " " + headerId + " || " + nodeKey + " || " + nodeVal)
				# check the grok has been correctly generated
				if grok == "":
					# empty grok, ie content transformation didn#t work, just say it
					lsconfFilter = CR + "# HEADER " + headerId + CR + "# line in RSA: " + rsaLine + CR + "# Parsing error!"
				else:
					# compose the filter section
					lsconfFilter = CR + "# HEADER " + headerId + CR + "filter {" + CR + t(1) + "if \"headerfound\" not in [tags] {" + CR + t(2) + "grok {" + CR
					lsconfFilter = lsconfFilter + t(3) + "# line in RSA: " + rsaLine + CR + t(3) + "match => {" + grok + "}" + CR + t(3) + "overwrite => [ \"message\" ]" + CR
					lsconfFilter = lsconfFilter + t(3) + "add_field => {" + CR + t(4) + "\"[rsa][header][id]\" => \"" + headerId + "\"" + CR
					# if no messageParserId, take the "messageid" field from parsing
					if messageParserId == "":
						lsconfFilter = lsconfFilter + t(4) + "\"[rsa][message][id2]\" => \"%{messageid}\"" + CR
					else:
						lsconfFilter = lsconfFilter + t(4) + "\"[rsa][message][id2]\" => \"" + messageParserId + "\"" + CR
					# other added fields from the <@field:value> in header content
					lsconfFilter = lsconfFilter + config.addedFields
					lsconfFilter = lsconfFilter + t(3) + "}" + CR
					lsconfFilter = lsconfFilter + t(3) + "add_tag => [ \"headerfound\" ]" + CR + t(2) + "}" + CR + t(1) + "}" + CR + "}"
				# write the filter block
				lsFile.write(lsconfFilter)
			# dealing with MESSAGE nodes
			if nodeName == "MESSAGE":
				for nodeKey in child.attrib:
					nodeVal = child.attrib[nodeKey]
					# get the id to add it as a new field
					if nodeKey == "id1":
						config.addedFields = config.addedFields + t(4) + "\"[event][id]\" => \"" + nodeVal + "\"" + CR
						config.addedFields = config.addedFields + t(4) + "\"[rsa][message][id1]\" => \"" + nodeVal + "\"" + CR
					if nodeKey == "id2":
						# matching with header on id2
						messageId = nodeVal
					# get the event category
					if nodeKey == "eventcategory":
						eventCategory = nodeVal
						config.addedFields = config.addedFields + t(4) + "\"[event][categoryid]\" => \"" + eventCategory + "\"" + CR
						if eventCategory in config.ecat: config.addedFields = config.addedFields + t(4) + "\"[event][category]\" => \"" + config.ecat[eventCategory] + "\"" + CR
					# get transformation functions and compute the corresponding mutates
					if nodeKey == "functions":
						nodeFunctions = nodeVal
						# get each part of the functions string (excluding < and >)
						functionParts = str.split(nodeFunctions[1: len(nodeVal)-1], "><")
						for functionPart in functionParts:
							# cut param + func
							kv = functionPart.split(":")
							k, v = "".join(kv[:1]), ":".join(kv[1:])
							if v[:9] == "*EVNTTIME":
								# compute the timestamp field
								dateFields = extractDateFields(v)
								dateFieldMutation = "%{" + dateFields.replace(",", "} %{") + "}"
								# extract date parsing and convert it to logstash format
								dateMatching = convertDate(v)
							elif v[:7] == "*STRCAT":
								catenateFields = convertStrcat(v)
								config.addedFields = config.addedFields + t(4) + "\"" + k.replace("@", "") + "\" => \"" + catenateFields + "\"" + CR
							elif v[:1] != "*":
								# static field
								config.addedFields = config.addedFields + t(4) + "\"" + k.replace("@", "") + "\" => \"" + v + "\"" + CR
						if config.DEBUG: print(nodeName + " " + messageId + " || " + nodeKey + " || " + nodeVal)
					if nodeKey == "content":
						rsaLine = nodeVal
						grok = transformMessageContent(nodeVal)
						if config.DEBUG: print(nodeName + " || " + nodeKey + " || " + nodeVal)
				# check the grok has been correctly generated
				if grok == "":
					# empty grok, ie content transformation didn#t work, just say it
					lsconfFilter = CR + "# MESSAGE " + messageId + CR + "# line in RSA: " + rsaLine + CR + "# Parsing error!"
				else:
					# compose the filter section
					lsconfFilter = CR + "# MESSAGE " + messageId + CR + "filter {" + CR + t(1) + "if \"messagefound\" not in [tags] and [rsa][message][id2] == \"" + messageId + "\" {" + CR + t(2) + "grok {" + CR
					lsconfFilter = lsconfFilter + t(3) + "# line in RSA: " + rsaLine + CR + t(3) + "match => {" + grok + "}" + CR
					lsconfFilter = lsconfFilter + t(3) + "add_field => {" + CR + config.addedFields
					# sometimes there is no date filter...
					if dateFields != "":
						lsconfFilter = lsconfFilter + t(4) + "\"fullDateTimeString\" => \"" + dateFieldMutation + "\"" + CR
					lsconfFilter = lsconfFilter + t(3) + "}" + CR
					lsconfFilter = lsconfFilter + t(3) + "add_tag => [ \"messagefound\" ]" + CR + t(3) + "# remove_field => [ \"message\" ]" + CR + t(2) + "}" + CR
					# sometimes there is no date filter...
					if dateFields != "":
						lsconfFilter = lsconfFilter + t(2) + "if [fullDateTimeString] {" + CR + t(3) + "date { match => [\"fullDateTimeString\", \"" + dateMatching + "\" ] }" + CR + t(2) + "}" + CR
					lsconfFilter = lsconfFilter + t(1) + "}" + CR + "}"
				# write the filter block
				lsFile.write(lsconfFilter)

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

		# enrich url
		with open(config.URL_FILTER_FILE,"r") as fi:
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

		# add the changes of names (ecs)
		lsFile.write(CR + "# Rename fields from RSA log parser meta field names in ECS (Elastic Common Schema) naming" + CR)
		lsFile.write("filter {" + CR + t(1) + "mutate {" + CR)
		for varKey in sorted(config.allFields):
			# jump over the fld* fields
			if varKey != "" and varKey[:3] != "fld" and varKey[:4] != "hfld":
				if varKey in config.ecsField:
					# field name exists in ECS mapping file, so change it
					lsFile.write(t(2) + "rename => { \"" + varKey + "\" => \"" + removeDots(config.ecsField[varKey]) + "\" }" + CR)
				else:
					# field name doesn't exist, rename it with general category "custom."
					lsFile.write(t(2) + "rename => { \"" + varKey + "\" => \"" + removeDots("custom." + varKey) + "\" }" + CR)
		lsFile.write(t(1) + "}" + CR + "}" + CR)

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

		# add output lines of logstash conf
		with open(config.OUTPUT_FILE,"r") as fi:
			lsFile.write(fi.read())

	print ("Conversion done!")

	# test the configuration file
	if config.CHECK_CONF:
		print("Starting Logstash to check the configuration...")
		cmd =  "\"" + str(config.LS_EXEC) + "\" -t -f " + str(config.LS_CONF_FILE) + " > " + str(config.LS_STDOUT_FILE) + " 2>&1"
		if config.DEBUG: print("Running Logstash config check: " + cmd)
		os.system(cmd)
		print("Logstash config test finished, see test results in output-logstash-configtest.txt")
