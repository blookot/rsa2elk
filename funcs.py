#!/usr/bin/env python

########################################################################
# RSA2ELK, by Vincent Maury
# Converts Netwitness log parser configuration to Logstash configuration
# see https://github.com/blookot/rsa2elk
########################################################################

import config
import re

# carriage return for logstash conf, just \n for linux
CR = "\n"

# insert n times a tab
def t(n):
    t=""
    for i in range(0,n):
        t=t+"\t"
    return t

# remove dots in field names
def removeDots(s):
    if "." in s:
        return "[" + s.replace(".","][") + "]"
    else:
        return s

# extract date fields from functions string, example is @event_time:*EVNTTIME($MSG,'%B %F %N:%U:%O %W',datetime)
def extractDateFields(s):
    eventtime = s.find("EVNTTIME")
    if eventtime != -1:
        # go to the third parameter of the EVENTTIME func to extract the field
        a = s.find(",",eventtime)
        if a != -1:
            b = s.find(",",a+1)
            if b>a:
                c = s.find(")",b+1)
                return s[b+1:c]
    return ""

# extract date parsing format from functions string and convert to logstash format
# change date, ref is https://community.rsa.com/docs/DOC-85016 pages 37-38 vs https://www.elastic.co/guide/en/logstash/current/plugins-filters-date.html#plugins-filters-date-match
# for example "10/Oct/2000:13:55:36 -0700" is parsed in RSA with "%D/%B/%W:%N:%U:%O" and "dd/MMM/yyyy:HH:mm:ss" in logstash
def convertDate(s):
    c = ""
    eventtime = s.find("EVNTTIME")
    if eventtime != -1:
        # extract the date format between the ''
        a = s.find("'",eventtime)
        if a != -1:
            b = s.find("'",a+1)
            if b>a:
                c = s[a+1:b]
                c = c.replace("%C", "M/d/yy H:m:s")
                c = c.replace("%R", "MMMM")
                c = c.replace("%B", "MMM")
                c = c.replace("%M", "MM")
                c = c.replace("%G", "M")
                c = c.replace("%D", "dd")
                c = c.replace("%F", "d")
                c = c.replace("%H", "HH")
                c = c.replace("%I", "HH")
                c = c.replace("%N", "H")
                c = c.replace("%T", "mm")
                c = c.replace("%U", "m")
                c = c.replace("%J", "D")
                c = c.replace("%P", "a")
                c = c.replace("%S", "ss")
                c = c.replace("%O", "s")
                c = c.replace("%Y", "yy")
                c = c.replace("%W", "yyyy")
                c = c.replace("%Z", "H:m:s")
                c = c.replace("%A", "D")
                c = c.replace("%X", "UNIX")
                if '%' in c and config.DEBUG: print("Missing a condition in date conversion")
    return c

# converting STRCAT
def convertStrcat(s):
    c = ""
    regex = re.compile("^[a-zA-Z]+.*")		# just saying the string starts with a letter
    # grab first (
    iFirstPar = s.find("(")
    iEndPar = s.find(")", iFirstPar)
    if iFirstPar > 0 and iEndPar > 0:
        idParts = str.split(s[iFirstPar+1:iEndPar], ",")
        # check for static strings vs fields
        for idPart in idParts:
            if "'" in idPart:
                # catenate a string
                c = c + str.strip(idPart.replace("'", ""))
            elif "\"" in idPart:
                # catenate a string
                c = c + str.strip(idPart.r("\"", ""))
            elif regex.match(idPart.strip()):
                # first character is [a-z] ie a field
                c = c + "%{" + idPart.strip() + "}"
            elif idPart == "\t":
                # just a tab
                c = c + "\\t"
            else:
                # any other char, just append
                c = c + idPart.strip()
        return c
    else:
        if config.DEBUG: print("Couldn't parse STRCAT string")
        return ""

# escaping " in grok content, and adding anchors if passed as param
def escapeGrok(s):
    if config.FULL_GROK_ANCHORS:
        return "\"^" + str.strip(s.replace("\"","\\\"")) + "$\""
    else:
        return "\"" + str.strip(s.replace("\"","\\\"")) + "\""

# escape special characters in grok :  \ . ^ $ * + - ? ( ) [ ] { } |
def escapeRegex(s):
    s = s.replace("\\", "\\\\"); s = s.replace(".", "\\."); s = s.replace("^", "\\^"); s = s.replace("$", "\\$")
    s = s.replace("*", "\\*"); s = s.replace("+", "\\+"); s = s.replace("-", "\\-"); s = s.replace("?", "\\?")
    s = s.replace("(", "\\("); s = s.replace(")", "\\)"); s = s.replace("[", "\\["); s = s.replace("]", "\\]")
    s = s.replace("{", "\\{"); s = s.replace("}", "\\}"); s = s.replace("|", "\\|")
    s = s.replace(chr(9), "\\t"); s = s.replace(chr(10), "\\n"); s = s.replace(chr(13), "\\r"); s = s.replace(" ", "\\s")
    return s