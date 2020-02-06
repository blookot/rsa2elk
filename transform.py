#!/usr/bin/env python

########################################################################
# RSA2ELK, by Vincent Maury
# Converts Netwitness log parser configuration to Logstash configuration
# see https://github.com/blookot/rsa2elk
########################################################################

from funcs import *
import config
import re


# transform a rsa parsing (with no alternative) into a dissect
def transformDissect(s):
	config.withDissect = True
	# RSA escapes < with << and { with {{ (there can't be alternatives in dissect)
	s = s.replace("<<",chr(220)).replace("{{","{")
	dissect = s
	# find all fields
	pattern = re.compile("<([^<>]*)>")
	for fld in pattern.finditer(s):
		newfld = "%{" + fld.group(1) + "}"
		dissect = dissect.replace(fld.group(0),newfld)
		# keep all fields for later mutate (ecs)
		config.allFields.add(fld.group(1))
	# put the static < back
	dissect = dissect.replace(chr(220),"<")
	return dissect


# get parsing string and compute the corresponding grok
def transformGrok(s, payloadField, finalDelimiter):
	config.withDissect = False
	grok = ""
	iChar = 0
	# go through the rsa parsing string char by char
	while iChar <= len(s):
		if s[iChar:iChar+1] == "<":
			# test if double << (< escaped)
			if s[iChar+1:iChar+2] == "<":
				grok = grok + "<"
				iChar = iChar + 2
			else:
				# begining of an RSA field
				endField = s.find(">",iChar)
				if endField > 0:
					fieldName = s[iChar + 1: endField]
					# if fieldname is the <!payload:payloadField> then insert the message "named group capture", cf grok guide
					if fieldName == payloadField:
						grok = grok + "(?<message>"
					# find next delimiter and forge grok by capturing everything but the delimiter char, for example:  (?<fld>[^\s]*)\s
					nextDelimiter = s[endField + 1: endField + 2]
					if nextDelimiter == "":
						# end of the string to parse, ie last field of the line
						if finalDelimiter == "":
							# must be the last field at the end of the string
							grok = grok + "(?<" + fieldName + ">.*)"
						else:
							# function called for alternatives {a|b}
							grok = grok + "(?<" + fieldName + ">[^" + escapeRegex(finalDelimiter) + "]*)"
					elif nextDelimiter == "{" and s[endField + 2: endField + 3] != "{":
						# field followed by alternatives, like <fld>{a|b} then next delimiter is the union of the first chars of each alternative
						alternatives = str.split(s[endField + 2: s.find("}", endField + 2)], "|")
						firstChars = ""
						for alternative in alternatives:
							if alternative[:1] == "<":
								# cannot be: <fld1>{a|<fld2>}
								if config.DEBUG: print ("Parsing error because of <fld1>{a|<fld2>}: couldn't parse " + s)
								config.parsingError = "Couldn't parse because of 2 adjacent fields like <fld1>{a|<fld2>}"
								return ""
							firstChars = firstChars + alternative[:1]
						grok = grok + "(?<" + fieldName + ">[^" + escapeRegex(firstChars) + "]*)"
					elif nextDelimiter == "<" and s[endField + 2: endField + 3] != "<":
						# <fld1><fld2> cannot work, to be dropped
						if config.DEBUG: print("Parsing error because of two fields: couldn't parse " + s)
						config.parsingError = "Couldn't parse because of 2 adjacent fields like <fld1><fld2>"
						return ""
					else:
						grok = grok + "(?<" + fieldName + ">[^" + escapeRegex(nextDelimiter) + "]*)"
					# keep all fields for later mutate (ecs)
					config.allFields.add (fieldName)
					iChar = endField + 1
				else:
					if config.DEBUG: print("Parsing error: couldn't find the end of the new field " + s)
					config.parsingError = "Couldn't find the end of the new field"
					return ""
		elif s[iChar:iChar+1] == "{":
			# test if double {{ ({ escaped)
			if s[iChar+1:iChar+2] == "{":
				grok = grok + "\\{"
				iChar = iChar + 2
			else:
				# parse alternatives
				endAlt = s.find("}",iChar)
				if endAlt > 0:
					# get the following character
					nextDelimiter = s[endAlt + 1: endAlt + 2]
					if nextDelimiter == "{" and s[endAlt + 2: endAlt + 3] != "{":
						# an alternative followed by another alternative, for ex {a|b}{c|d} then next delimiter is the union of the first chars of each alternative
						alternatives = str.split(s[endAlt + 2: s.find("}", endAlt + 2)], "|")
						nextDelimiter = ""
						for alternative in alternatives:
							nextDelimiter = nextDelimiter + alternative[:1]
					elif nextDelimiter == "<" and s[endAlt + 2: endAlt + 3] != "<":
						# an alternative followed by a field: each alternative shouldn't end with a field, like "{stuff|other <fld1>}<fld2>" is impossible
						nextDelimiter = ""
					# split alternatives and call this fonction for each alternative (recursive powah!!)
					grok = grok + "("
					alternatives = str.split(s[iChar + 1: endAlt], "|")
					for alternative in alternatives:
						grok = grok + transformGrok(alternative, "", nextDelimiter) + "|"
					grok = grok[:-1] + ")"
					iChar = endAlt + 1
		elif s[iChar:iChar+1] == " ":
			# by default, all spaces should be grouped into a [\s]+, unless SINGLE_SPACE option specified
			if config.SINGLE_SPACE:
				grok = grok + "\s"
			else:
				grok = grok + "[\s]+"
			iChar = iChar + 1
			while iChar <= len(s) and s[iChar: iChar+1] == " ":
				iChar = iChar + 1
		elif s[iChar:iChar+1] != "" and s[iChar:iChar+1] in config.ADD_STOP_ANCHORS:
			# one of the hard stop characters
			grok = grok + "(?<anchorfld" + str(config.anchorFldId) + ">[^" + escapeRegex(s[iChar:iChar+1]) + "]*)" + escapeRegex(s[iChar: iChar+1])
			config.anchorFldId = config.anchorFldId + 1
			iChar = iChar + 1
		else:
		# all other characters
			grok = grok + escapeRegex(s[iChar: iChar+1])
			iChar = iChar + 1

	# if there was a payload field, end the )
	if payloadField != "":
		grok = grok + ")"

	return grok



# transform functions
def transformFunctions(s):
	# get each part of the functions string (excluding < and >)
	pattern = re.compile("<@([a-z_]+):([^>]+)>")
	# keep the list of fields, because sometimes they are defined twice! like in devices/astarosg/astarosgmsg.xml
	newFuncFields = set()
	for rsaFunc in pattern.finditer(s):
		k, v = rsaFunc.group(1), rsaFunc.group(2)
		# check if this field hasn't been read yet
		if k in newFuncFields:
			# again the same field!
			if config.DEBUG: print ("The field " + k + "is defined twice in " + s)
		else:
			if v[:9] == "*EVNTTIME":
				# form: @event_time:*EVNTTIME($MSG,'%B %F %N:%U:%O %W',datetime)
				# sometimes used for other fields than event_time, so we check first
				if k == "event_time":
					# compute the timestamp field
					config.dateFieldMutation = "%{" + "} %{".join(re.findall(",([a-z0-9\._]+)", v)) + "}"
					config.dateMatching = convertDate(v)
			elif v[:7] == "*STRCAT":
				# transform <@fld:*STRCAT(a,b)> for instance
				catenateFields = convertStrcat(v)
				if k == "msg_id":
					config.messageId = catenateFields
				else:
					config.addedFields = config.addedFields + t(4) + "\"" + k + "\" => \"" + catenateFields + "\"" + CR
			elif v[:8] == "*PARMVAL":
				# transform <@fld1:*PARMVAL(fld2)> for instance (that copies fld2 in fld1)
				if k != "msg":
					if k == "msg_id":
						config.messageId = "%{" + v[9:-1] + "}"
					else:
						config.addedFields = config.addedFields + t(4) + "\"" + k + "\" => \"%{" + v[9:-1] + "}\"" + CR
			elif v[:4] == "*HDR":
				# transform <@fld:*HDR(hfld)> for instance (that copies a header field hfld in fld)
				if k != "msg":
					if k == "msg_id":
						config.messageId = "%{" + v[5:-1] + "}"
					else:
						config.addedFields = config.addedFields + t(4) + "\"" + k + "\" => \"%{" + v[5:-1] + "}\"" + CR
			elif v[:1] == "*":
				# let's see if it's one of the functions defined in the valuemap, in the form of @ec_activity:*getEventCategoryActivity(action)
				getValueMap(k,v)
			elif v[:1] != "*":
				# static field
				config.addedFields = config.addedFields + t(4) + "\"" + k + "\" => \"" + v + "\"" + CR
			# record the field anyway
			newFuncFields.add(k)
			# keep all fields for later mutate (ecs)
			config.allFields.add(k)
		# anyway (recognized func or not), delete it
		s = s.replace(rsaFunc.group(0),"")
	# when further parsing is planned, return the string with no funcs
	return s


# read the full rsa line and extract funcs and use dissect if there is no alternatives, or grok
def transformFullRsaLine(s, msgField, payloadField):
	msgMatch = ""
	# check if the string ends with a \ which is not supported, see issue https://github.com/elastic/logstash/issues/9701
	if s[-1:] == "\\":
		config.parsingError = "String ends with a \\ which is not supported, see issue https://github.com/elastic/logstash/issues/9701"
		return ""
	# find potential funcs and extract them
	s = transformFunctions(s)
	# if payload field is not empty, use grok anyway
	if payloadField != "":
		msgMatch = escapeGrok(transformGrok(s,payloadField,""))
	else:
		# look for alternatives
		withAlternatives = False
		pattern = re.compile("{")
		for alternative in re.finditer(pattern, s):
			# check if it's an escaped {
			if s[alternative.start():alternative.start()+2] != "{{":
				withAlternatives = True
		# if there are alternatives, use grok, otherwise we can use dissect
		if withAlternatives:
			msgMatch = escapeGrok(transformGrok(s,payloadField,""))
		else:
			msgMatch = escapeDissect(transformDissect(s))
	# get the message and return the full line
	return "\"" + msgField + "\" => " + msgMatch


# get parsing string for a header and compute the corresponding dissect
def transformHeaderContent(s):
	# first, deal with <!payload> field (only in headers)
	payloadField = ""
	iPayload = s.find("<!payload")
	if iPayload >= 0:
		endPayload = s.find(">",iPayload)
		if endPayload > 0:
			# check for a field in the payload tag
			if s[iPayload + 9: iPayload + 10] == ":":
				payloadField = s[iPayload + 10: endPayload]
				# replace it by a normal "payload" field because the "message" field (parsed by message content) will start at the payload field
				s = s.replace(s[iPayload: endPayload + 1], "<payload>")
			else:
				# the "message" field is at the end
				s = s.replace(s[iPayload: endPayload + 1], "<message>")
		else:
			if config.DEBUG: print("Error in payload field: " + s)
	else:
		if config.DEBUG: print("Error in payload field, missing payload: " + s)
	# return the match
	return transformFullRsaLine(s, "[event][original]", payloadField)


# get parsing string for a message and compute the corresponding dissect
def transformMessageContent(s):
	# return the dissect match
	return transformFullRsaLine(s, "message", "")

