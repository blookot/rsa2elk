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
import json
import base64


def convertFile():

	# First checking that mandatory files exist
	if path.exists(config.MAPPING_FILE) and path.exists(config.XML_FILE) and path.exists(config.ECAT_FILE) and path.exists(config.INPUT_FILE) and path.exists(config.OUTPUT_FILE):

		print("*** Starting file conversion for " + str(config.XML_FILE))
		# get ecs mapping from file
		initMapping()

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
			rsaConfigName = ""; rsaConfigDisplayName = ""; rsaConfigGroup = ""
			# read DEVICEMESSAGES attributes to get config names
			with open(config.XML_FILE, 'r', encoding='iso-8859-1') as xml_file:
				xmlp = et.XMLParser(encoding='iso-8859-1')
				tree = et.parse(xml_file,parser=xmlp)
				root = tree.getroot()
				# when there are attributes (sometimes empty, like cef.xml)
				if len(root.attrib) > 0:
					for nodeKey in root.attrib:
						nodeVal = root.attrib[nodeKey]
						if nodeKey == "name": rsaConfigName = nodeVal
						if nodeKey == "displayname": rsaConfigDisplayName = nodeVal
						if nodeKey == "group": rsaConfigGroup = nodeVal
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
									# sometimes insertbefore, sometimes insertBefore => support both!
									insertBefore = childCustom.get('insertbefore')
									if insertBefore is None: insertBefore = childCustom.get('insertBefore')
									insertAfter = childCustom.get('insertafter')
									if insertAfter is None: insertAfter = childCustom.get('insertAfter')
									# replace child when id matches
									if child.get('id1') == childCustom.get('id1') and insertBefore is None and insertAfter is None:
										if config.DEBUG: print("Replace " + childCustom.get('id1'))
										root.remove(child)
										root.insert(childIndex, childCustom)
										break
									# insert before. note that if there are 2 insertbefore, the second one will be after the first in the resulting config
									elif insertBefore == child.get('id1') and insertBefore is not None:
										root.insert(childIndex, childCustom)
										if config.DEBUG: print("Insert " + childCustom.get('id1') + " before " + insertBefore)
										break
									# insert after. note that if there are 2 insertafter, the second one will be before the first in the resulting config
									elif insertAfter == child.get('id1') and insertAfter is not None:
										root.insert(childIndex+1, childCustom)
										if config.DEBUG: print("Insert " + childCustom.get('id1') + " after " + insertAfter)
										break
									else:
										childIndex = childIndex + 1

				# build the structure of headers and messages
				for child in root:
					nodeName = child.tag
					if nodeName == "HEADER":
						headerId = ""; headerMessageId = ""; headerContent = ""
						for nodeKey in child.attrib:
							nodeVal = child.attrib[nodeKey]
							if nodeKey == "id2": headerId = nodeVal
							if nodeKey == "messageid": headerMessageId = nodeVal
							if nodeKey == "content": headerContent = nodeVal
						config.headers.append({"headerId": headerId, "headerMessageId": headerMessageId, "headerContent": headerContent})
					if nodeName == "MESSAGE":
						messageId1 = ""; messageId2 = ""; eventCategory = ""; messageFunctions = ""; messageContent = ""
						for nodeKey in child.attrib:
							nodeVal = child.attrib[nodeKey]
							if nodeKey == "id1": messageId1 = nodeVal
							if nodeKey == "id2": messageId2 = nodeVal
							if nodeKey == "eventcategory": eventCategory = nodeVal
							if nodeKey == "functions": messageFunctions = nodeVal
							if nodeKey == "content": messageContent = nodeVal
						config.messages.append({"messageId1": messageId1, "messageId2": messageId2, "eventCategory": eventCategory, "messageFunctions": messageFunctions, "messageContent": messageContent})
						# record a new parser
						if config.msgParsers.count(messageFunctions+messageContent) == 0: config.msgParsers.append(messageFunctions+messageContent)
						msgParserId = config.msgParsers.index(messageFunctions+messageContent)
						# store an alternative dict structure of id2s for easier access
						if messageId2 in config.id2s:
							config.id2s[messageId2]["nbId1"] = config.id2s[messageId2]["nbId1"] + 1
						else:
							config.id2s[messageId2] = {"nbId1": 1, "msgParserId": msgParserId, "messageId1": messageId1, "eventCategory": eventCategory, "messageFunctions": messageFunctions, "messageContent": messageContent}
					# read the VALUEMAP nodes to enrich messages
					if nodeName == "VALUEMAP":
						parsingOK = True
						for nodeKey in child.attrib:
							nodeVal = child.attrib[nodeKey]
							if nodeKey == "name": vmName = nodeVal
							if nodeKey == "default": vmDefault = nodeVal.replace("$NONE","")
							if nodeKey == "keyvaluepairs":
								# first convert the value into a dict
								try:
									vmKV = dict( (k.strip(), v.replace("'","").strip()) for k,v in (item.split('=') for item in nodeVal.split('|')) )
								except:
									parsingOK = False
									if config.DEBUG: print("Error in VALUEMAP: " + nodeVal)
						# finally populate the vm dict
						if parsingOK: config.valueMap[vmName] = {"default": vmDefault, "kv": vmKV}
					# special for cef.xml
					if nodeName == "VendorProducts":
						for v2d in child:
							vendor = ""; product = ""; device = ""; group = ""
							for nodeKey in v2d.attrib:
								if nodeKey == "vendor": vendor = v2d.attrib[nodeKey]
								if nodeKey == "product": product = v2d.attrib[nodeKey]
								if nodeKey == "device": device = v2d.attrib[nodeKey]
								if nodeKey == "group": group = v2d.attrib[nodeKey]
							# record the vendor2device table for later use
							config.vendorToDevice.append({"vendor": vendor, "product": product, "device": device, "group": group})

				# dump the json mapping msgid2 -> parserid (when only 1 id1)
				with open(config.MSG2PARSER_DICT_FILE,"w",newline=None,encoding="utf-8") as parserMappingFile:
					parserMapping = dict()
					for msgId2 in config.id2s:
						if config.id2s[msgId2]["nbId1"] == 1:
							parserMapping[msgId2] = "msgParserId" + str(config.id2s[msgId2]["msgParserId"])
						else:
							parserMapping[msgId2] = msgId2
					# parserMappingFile.write(json.dumps(config.msg2group, indent=4))
					parserMappingFile.write(json.dumps(parserMapping, indent=4))


			###############################################################################
			############################### Convert headers ###############################
			###############################################################################

			lsFile.write(CR + CR + "# One single filter block for all headers and messages" + CR + "filter {" + CR + CR + "################## HEADERS ##################" + CR + CR)
			for iHeader,header in enumerate(config.headers):
				config.dateFieldMutation = ""; config.dateMatching = ""; config.messageId = ""; config.addedFields = ""; config.parsingError = ""
				# perform the 2 transformations
				messageParserId = convertStrcat(header["headerMessageId"])
				msgMatch = transformHeaderContent(header["headerContent"])
				# check the msgMatch has been correctly generated
				if config.parsingError != "":
					# content transformation didn't work, just say it
					lsconfFilter = t(1) + "# HEADER " + header["headerId"] + CR + t(1) + "# line in RSA: " + header["headerContent"] + CR + t(1) + "# Parsing error: " + config.parsingError + CR
				else:
					# compose the filter section
					lsconfFilter = t(1) + "# HEADER " + header["headerId"] + CR + t(1) + "# line in RSA: " + header["headerContent"] + CR + t(1) + "if ![logstash][headerfound] {" + CR 
					if config.withDissect:
						lsconfFilter = lsconfFilter + t(2) + "dissect {" + CR + t(3) + "mapping => { " + msgMatch + " }" + CR
					else:
						lsconfFilter = lsconfFilter + t(2) + "grok {" + CR + t(3) + "match => { " + msgMatch + " }" + CR 
					# add a filter id for monitoring purpose
					lsconfFilter = lsconfFilter + t(3) + "id => \"header-" + escapeString(header["headerId"]) + "\"" + CR
					# add header id for debugging
					lsconfFilter = lsconfFilter + t(3) + "add_field => {" + CR + t(4) + "\"[rsa][header][id]\" => \"" + escapeString(header["headerId"]) + "\"" + CR
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
					lsconfFilter = lsconfFilter + t(1) + "}" + CR

				# write the filter block for this header
				lsFile.write(lsconfFilter)


			##########################################################################################
			############################### Enrich and link to parsers ###############################
			##########################################################################################

			# make the translation from messageid2 to msgGroupId
			lsFile.write(CR + CR + CR + "################## MsgId2 to Parser ##################" + CR + CR)
			lsFile.write(t(1) + "translate {" + CR)
			lsFile.write(t(2) + "field => \"[rsa][message][id2]\"" + CR)
			lsFile.write(t(2) + "destination => \"[logstash][msgparser][id]\"" + CR)
			lsFile.write(t(2) + "dictionary_path => \"msgid2parserid-" + config.DEVICE + ".json\"" + CR)
			lsFile.write(t(2) + "fallback => \"\"" + CR)
			lsFile.write(t(2) + "override => true" + CR)
			lsFile.write(t(1) + "}" + CR)

			# if cef.xml, add the translate section from vendor2device before the first message
			if config.DEVICE_FNAME == "cef.xml":
				lsFile.write(CR + CR + CR + "################## Vendor2Device ##################" + CR + CR)
				lsFile.write(t(1) + "translate {" + CR)
				lsFile.write(t(2) + "field => \"[rsa][message][id2]\"" + CR)
				lsFile.write(t(2) + "destination => \"[rsa][message][id2]\"" + CR)
				lsFile.write(t(2) + "dictionary => {" + CR)
				for v2d in config.vendorToDevice:
					lsFile.write(t(3) + "\"" + config.vendorToDevice[v2d]["vendor"] + config.vendorToDevice[v2d]["product"] + "\" => \"" + config.vendorToDevice[v2d]["device"] + "\"" + CR)
				lsFile.write(t(2) + "}" + CR)
				lsFile.write(t(2) + "fallback => \"\"" + CR)
				lsFile.write(t(2) + "override => true" + CR)
				lsFile.write(t(1) + "}" + CR)


			################################################################################
			############################### Convert messages ###############################
			################################################################################

			if not config.HEADERS_ONLY:
				lsFile.write(CR + CR + "################## MESSAGES ##################" + CR + CR)
				firstMsg = True
				addedParser = [] 	# record the parsers added to avoid duplicating
				# go through all messageId2
				for id2,msgId2 in enumerate(config.id2s):
					config.dateFieldMutation = ""; config.dateMatching = ""; config.messageId = ""; config.addedFields = ""; config.parsingError = ""
					# if only 1 MESSAGE for this messageId2, link (between header & message) using parserId
					if config.id2s[msgId2]["nbId1"] == 1:
						# check if we haven't already met this parser
						if addedParser.count(config.id2s[msgId2]["msgParserId"]) == 0:
							# perform transformations
							transformFunctions(config.id2s[msgId2]["messageFunctions"])
							msgMatch = transformMessageContent(config.id2s[msgId2]["messageContent"])
							# check the msgMatch has been correctly generated
							if config.parsingError != "":
								# content transformation didn't work, just say it
								lsconfFilter = t(1) + "# PARSER msgParserId" + str(config.id2s[msgId2]["msgParserId"]) + CR + t(1) + "# line in RSA: " + config.id2s[msgId2]["messageContent"] + CR + t(1) + "# Parsing error: " + config.parsingError + CR
							else:
								# compose the filter section
								lsconfFilter = t(1) + "# PARSER msgParserId" + str(config.id2s[msgId2]["msgParserId"]) + CR + t(1) + "# line in RSA: " + config.id2s[msgId2]["messageContent"] + CR
								if firstMsg:
									lsconfFilter = lsconfFilter + t(1) + "if [logstash][msgparser][id] == \"msgParserId" + str(config.id2s[msgId2]["msgParserId"]) + "\" {" + CR
								else:
									lsconfFilter = lsconfFilter + t(1) + "else if [logstash][msgparser][id] == \"msgParserId" + str(config.id2s[msgId2]["msgParserId"]) + "\" {" + CR
								if config.withDissect:
									lsconfFilter = lsconfFilter + t(2) + "dissect {" + CR + t(3) + "mapping => { " + msgMatch + " }" + CR
								else:
									lsconfFilter = lsconfFilter + t(2) + "grok {" + CR + t(3) + "match => { " + msgMatch + " }" + CR
								# add a filter id for monitoring purpose
								lsconfFilter = lsconfFilter + t(3) + "id => \"msgParserId" + str(config.id2s[msgId2]["msgParserId"]) + "\"" + CR
								lsconfFilter = lsconfFilter + t(3) + "add_field => {" + CR + config.addedFields
								# sometimes there is no date filter...
								if config.dateFieldMutation != "":
									lsconfFilter = lsconfFilter + t(4) + "\"[logstash][fullDateTimeString]\" => \"" + config.dateFieldMutation + "\"" + CR
								lsconfFilter = lsconfFilter + t(4) + "\"[logstash][messagefound]\" => true" + CR + t(3) + "}" + CR + t(2) + "}" + CR
								# sometimes there is no date filter...
								if config.dateFieldMutation != "":
									lsconfFilter = lsconfFilter + t(2) + "if [logstash][fullDateTimeString] {" + CR + t(3) + "date { match => [ \"[logstash][fullDateTimeString]\", " + config.dateMatching + " ] }" + CR + t(2) + "}" + CR
								lsconfFilter = lsconfFilter + t(1) + "}" + CR
							# write the filter block
							lsFile.write(lsconfFilter)
							# add the parser to the list
							addedParser.append(config.id2s[msgId2]["msgParserId"])
						# anyway, not the first message anymore!
						firstMsg = False
					
					# now if there is several messages (several id1) for 1 id2: loop through id1s
					else:
						# start with the elseif for this id2
						if firstMsg:
							lsFile.write(t(1) + "if [logstash][msgparser][id] == \"" + escapeString(msgId2) + "\" {" + CR)
						else:
							lsFile.write(t(1) + "else if [logstash][msgparser][id] == \"" + escapeString(msgId2) + "\" {" + CR)
						# loop through the id1s that have this msgId2
						for iMessage,message in enumerate(config.messages):
							config.dateFieldMutation = ""; config.dateMatching = ""; config.messageId = ""; config.addedFields = ""; config.parsingError = ""
							if message["messageId2"] == msgId2:
								config.messageId = message["messageId1"]
								# perform transformations
								transformFunctions(message["messageFunctions"])
								msgMatch = transformMessageContent(message["messageContent"])
								# check the msgMatch has been correctly generated
								if config.parsingError != "":
									# content transformation didn't work, just say it
									lsconfFilter = t(2) + "# MESSAGE " + message["messageId1"] + CR + t(2) + "# line in RSA: " + message["messageContent"] + CR + t(2) + "# Parsing error: " + config.parsingError + CR
								else:
									# compose the filter section
									lsconfFilter = t(2) + "# MESSAGE " + message["messageId1"] + CR + t(2) + "# line in RSA: " + message["messageContent"] + CR
									lsconfFilter = lsconfFilter + t(2) + "if ![logstash][messagefound] {" + CR
									if config.withDissect:
										lsconfFilter = lsconfFilter + t(3) + "dissect {" + CR + t(4) + "mapping => { " + msgMatch + " }" + CR
									else:
										lsconfFilter = lsconfFilter + t(3) + "grok {" + CR + t(4) + "match => { " + msgMatch + " }" + CR
									# add a filter id for monitoring purpose
									lsconfFilter = lsconfFilter + t(4) + "id => \"message-" + escapeString(message["messageId1"]) + "\"" + CR
									# add new fields
									config.addedFields = config.addedFields + t(5) + "\"[event][id]\" => \"" + escapeString(config.messageId) + "\"" + CR
									config.addedFields = config.addedFields + t(5) + "\"[rsa][message][id1]\" => \"" + escapeString(message["messageId1"]) + "\"" + CR
									# add event category
									config.addedFields = config.addedFields + t(5) + "\"[event][categoryid]\" => \"" + message["eventCategory"] + "\"" + CR
									# enrich event category (performed by a later dict)
									# if message["eventCategory"] in config.ecat: config.addedFields = config.addedFields + t(5) + "\"[event][category]\" => \"" + config.ecat[message["eventCategory"]] + "\"" + CR
									lsconfFilter = lsconfFilter + t(4) + "add_field => {" + CR + config.addedFields
									# sometimes there is no date filter...
									if config.dateFieldMutation != "":
										lsconfFilter = lsconfFilter + t(5) + "\"[logstash][fullDateTimeString]\" => \"" + config.dateFieldMutation + "\"" + CR
									lsconfFilter = lsconfFilter + t(5) + "\"[logstash][messagefound]\" => true" + CR + t(4) + "}" + CR + t(3) + "}" + CR
									# sometimes there is no date filter...
									if config.dateFieldMutation != "":
										lsconfFilter = lsconfFilter + t(3) + "if [logstash][fullDateTimeString] {" + CR + t(4) + "date { match => [ \"[logstash][fullDateTimeString]\", " + config.dateMatching + " ] }" + CR + t(3) + "}" + CR
									lsconfFilter = lsconfFilter + t(2) + "}" + CR

								# write the filter block
								lsFile.write(lsconfFilter)
						
						# once all id1s converted, close the id2 if
						lsFile.write(t(1) + "}" + CR)
						# anyway, not the first message anymore!
						firstMsg = False					
					
				# visual separator after all messages
				lsFile.write(CR + CR + "################## END OF MESSAGES ##################")

			# end of the filter block
			lsFile.write(CR + CR + "# End of the filter block" + CR + "}" + CR)


			###########################################################################
			############################### Enrichments ###############################
			###########################################################################

			# TODO: add a translate to get id1 and event category id for id2s that have only 1 id1

			# # enrich category id -> category name
			# lsFile.write(CR + "# Enrich event category" + CR)
			# # if message["eventCategory"] in config.ecat: config.addedFields = config.addedFields + t(5) + "\"[event][category]\" => \"" + config.ecat[message["eventCategory"]] + "\"" + CR
			# lsFile.write("translate {" + CR)
			# lsFile.write(t(1) + "field => \"[event][categoryid]\"" + CR)
			# lsFile.write(t(1) + "destination => \"[event][category]\"" + CR)
			# lsFile.write(t(1) + "dictionary_path => \"ecat.ini\"" + CR)
			# lsFile.write(t(1) + "fallback => \"\"" + CR)
			# lsFile.write(t(1) + "override => true" + CR)
			# lsFile.write("}" + CR)

			# enrich using VALUEMAP, see https://www.elastic.co/guide/en/logstash/current/plugins-filters-translate.html
			if len(config.valueMap) > 0:
				lsFile.write(CR + "# Enrich events using VALUEMAP" + CR)
			for vm in config.valueMap:
				# sometimes value maps are not used in messages, so let's check this first!
				if "fld" in config.valueMap[vm]:
					lsFile.write("filter {" + CR + t(1) + "translate {" + CR)
					lsFile.write(t(2) + "field => \"[" + config.valueMap[vm]["fld"] + "]\"" + CR)
					lsFile.write(t(2) + "destination => \"[" + config.valueMap[vm]["newFld"] + "]\"" + CR)
					lsFile.write(t(2) + "dictionary => {" + CR)
					for k,v in config.valueMap[vm]["kv"].items():
						lsFile.write(t(3) + "\"" + k + "\" => \"" + v + "\"" + CR)
					lsFile.write(t(2) + "}" + CR)
					lsFile.write(t(2) + "fallback => \"" + config.valueMap[vm]["default"] + "\"" + CR)
					lsFile.write(t(2) + "override => true" + CR)
					lsFile.write(t(1) + "}" + CR + "}" + CR)

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

			# add the changes of names (ecs) or remove the .
			lsRenames = ""
			for varKey in sorted(config.allFields):
				# jump over the fld* fields
				if varKey != "" and varKey[:3] != "fld" and varKey[:4] != "hfld":
					if config.RENAME_FIELDS:
						if varKey in config.ecsField:
							# field name exists in ECS mapping file, so change it
							lsRenames = lsRenames + t(3) + "\"" + varKey + "\" => \"" + removeDots(config.ecsField[varKey]) + "\"" + CR
						else:
							# field name doesn't exist, rename it with general category "custom."
							lsRenames = lsRenames + t(3) + "\"" + varKey + "\" => \"" + removeDots("custom." + varKey) + "\"" + CR
					elif "." in varKey:
						# just remove a possible . in field name
						lsRenames = lsRenames + t(3) + "\"" + varKey + "\" => \"" + varKey.replace(".","_") + "\"" + CR
			if lsRenames != "":
				lsFile.write(CR + "# Rename fields" + CR)
				lsFile.write("filter {" + CR + t(1) + "mutate {" + CR + t(2) + "rename => {" + CR + lsRenames)
				lsFile.write(t(2) + "}" + CR + t(1) + "}" + CR + "}" + CR)

			# drop all hfld* and fld* fields
			if config.REMOVE_UNNAMED_FIELDS:
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
				lsFile.write(t(2) + "mutate { remove_field => [ " + ("\"[event][original]\", " if config.REMOVE_ORIG_MSG else "") + "\"message\", \"payload\", \"[logstash][fullDateTimeString]\", \"[rsa][msg][data]\", \"[rsa][msg][id]\", \"[rsa][header][id]\", \"[rsa][message][id1]\", \"[rsa][message][id2]\" ] }" + CR)
				lsFile.write(t(1) + "}" + CR + "}" + CR)

			# add output lines of logstash conf
			with open(config.OUTPUT_FILE,"r") as fi:
				# just replace the template name with the name (as the template key doesn't support field notation)
				lsFile.write(fi.read().replace("%{template_name}",rsaConfigName).replace("%{device_name}",config.DEVICE))

			print ("Conversion done! See output file: " + str(config.LS_CONF_FILE))


		##########################################################################
		############################### ES mapping ###############################
		##########################################################################

		# generate the index mapping for ES
		with open(config.ES_MAPPING_FILE,"w",newline=None,encoding="utf-8") as esMappingFile:
			# write settings
			config.esMap["index_patterns"] = rsaConfigName + "*"
			config.esMap["settings"]["number_of_shards"] = config.NB_SHARDS
			config.esMap["settings"]["number_of_replicas"] = config.NB_REPLICAS
			config.esMap["settings"]["index.refresh_interval"] = config.REFRESH_INTERVAL
			# write mandatory timestamp & version fields
			config.esMap["mappings"]["properties"]["@timestamp"] = { "type" : "date" }
			config.esMap["mappings"]["properties"]["@version"] = { "type" : "keyword" }
			# write geopoint mapping
			config.esMap["mappings"]["properties"]["geo"]["properties"]["location"] = { "type" : "geo_point" }
			config.esMap["mappings"]["properties"]["source"]["properties"]["geo"]["properties"]["location"] = { "type" : "geo_point" }
			config.esMap["mappings"]["properties"]["destination"]["properties"]["geo"]["properties"]["location"] = { "type" : "geo_point" }
			config.esMap["mappings"]["properties"]["host"]["properties"]["geo"]["properties"]["location"] = { "type" : "geo_point" }
			config.esMap["mappings"]["properties"]["observer"]["properties"]["geo"]["properties"]["location"] = { "type" : "geo_point" }
			# write ids
			config.esMap["mappings"]["properties"]["event"]["properties"]["id"] = { "type" : "keyword" }
			config.esMap["mappings"]["properties"]["rsa"]["properties"]["header"]["properties"]["id"] = { "type" : "keyword" }
			config.esMap["mappings"]["properties"]["rsa"]["properties"]["message"]["properties"]["id1"] = { "type" : "keyword" }
			config.esMap["mappings"]["properties"]["rsa"]["properties"]["message"]["properties"]["id2"] = { "type" : "keyword" }
			# write field mapping
			for varKey in sorted(config.allFields):
				# jump over the fld* fields
				if varKey != "" and varKey[:3] != "fld" and varKey[:4] != "hfld":
					# if field doesn't exist in ECS mapping, we don't care, we'll just leave them as they are (indexed as text)
					if varKey in config.ecsField:
						# if type is text, we let ES create the field and the field.keyword automatically
						if config.RENAME_FIELDS and config.ecsType[varKey] != "text":
							# fields have been renamed in LS
							generateFieldMapping(config.ecsField[varKey], config.ecsType[varKey])
						if not config.RENAME_FIELDS and config.ecsType[varKey] != "text":
							# just keeping the raw RSA field name, but changing the type
							generateFieldMapping(varKey.replace(".","_"), config.ecsType[varKey])
					else:
						# TODO support table-map.xml to change types of fields that are custom
						if config.DEBUG: print("TODO")
			# write the list of fields (without the last comma)
			esMappingFile.write(json.dumps(config.esMap, indent=4))


		##################################################################################
		############################### Testing the config ###############################
		##################################################################################

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
