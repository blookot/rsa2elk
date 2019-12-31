#!/usr/bin/env python

########################################################################
# RSA2ELK, by Vincent Maury
# Converts Netwitness log parser configuration to Logstash configuration
# see https://github.com/blookot/rsa2elk
########################################################################

from funcs import *
import config


# get parsing string and compute the corresponding grok
def transformContent(s, payloadField, finalDelimiter):
	grok = ""
	iChar = 0
	# go through the rsa parsing string char by char
	while iChar <= len(s):
		if s[iChar:iChar+1] == "<":
			# test if double << (< escaped)
			if s[iChar+1:iChar+2] == "<":
				grok = grok + "<"
				iChar = iChar + 2
			elif s[iChar+1:iChar+2] == "@":
				# old <@fld:stuff> notation meaning a new field "perimeter" should be set to "sgt"
				# can also be <@fld:*STRCAT(a,b)> for instance
				endNewField = s.find(">",iChar)
				if endNewField > 0:
					sub = s[iChar+1:endNewField]
					kv = sub.split(":")
					k, v = "".join(kv[:1]), ":".join(kv[1:])
					if v[:7] == "*STRCAT":
						catenateFields = convertStrcat(v)
						config.addedFields = config.addedFields + t(4) + "\"" + k[1:] + "\" => \"" + catenateFields + "\"" + CR
						# keep all fields for later mutate (ecs)
						config.allFields.add(k[1:])
					elif v[:1] != "*":
						# static field
						config.addedFields = config.addedFields + t(4) + "\"" + k[1:] + "\" => \"" + v + "\"" + CR
						# keep all fields for later mutate (ecs)
						config.allFields.add(k[1:])
					else:
						if config.DEBUG: print("Error in new field <@fld:stuff> notation (unsupported value): " + sub)
				else:
					if config.DEBUG: print("Error in new field <@fld:stuff> notation (no closing >): " + s)
				iChar = endNewField + 1
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
								return ""
							firstChars = firstChars + alternative[:1]
						grok = grok + "(?<" + fieldName + ">[^" + escapeRegex(firstChars) + "]*)"
					elif nextDelimiter == "<" and s[endField + 2: endField + 3] != "<":
						# <fld1><fld2> cannot work, to be dropped
						if config.DEBUG: print("Parsing error because of two fields: couldn't parse " + s)
						return ""
					else:
						grok = grok + "(?<" + fieldName + ">[^" + escapeRegex(nextDelimiter) + "]*)"
					# keep all fields for later mutate (ecs)
					config.allFields.add (fieldName)
					iChar = endField + 1
		elif s[iChar:iChar+1] == "{":
			# test if double {{ ({ escaped)
			if s[iChar+1:iChar+2] == "{":
				grok = grok + "\{"
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
						grok = grok + transformContent(alternative, "", nextDelimiter) + "|"
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


# get parsing string for a header and compute the corresponding grok
def transformHeaderContent(s):
	# first, deal with <!payload> field (only in headers)
	payloadField = ""
	iPayload = s.find("<!payload")
	if iPayload > 0:
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
	# return the grok match
	grok = transformContent(s, payloadField, "")
	if grok == "":
		return ""
	else:
		return " \"[event][original]\" => " + escapeGrok(grok)


# get parsing string for a message and compute the corresponding grok
def transformMessageContent(s):
	# return the grok match
	grok = transformContent(s, "", "")
	if grok == "":
		return ""
	else:
		return " \"message\" => " + escapeGrok(grok)

