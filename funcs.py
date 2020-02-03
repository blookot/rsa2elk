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

def convertDate(s):
    dateList = set()
    pattern = re.compile(",'([^']+)'")
    for dStr in pattern.finditer(s):
        c = dStr.group(1)
        # replace the specific chars by their logstash date filter equivalent
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
        c = c.replace("%Q", "a")    # AM/PM
        c = c.replace("%K", "")    # undocumented... seen in cef.xml
        c = c.replace("%L", "")    # undocumented... seen in cef.xml
        c = c.replace("%E", "")    # undocumented... seen in v20_trendmicromsg.xml
        c = c.replace("%X", "UNIX")
        if '%' in c: print("Missing a condition in date conversion: " + c)
        dateList.add(c)
    return "\"" + "\", \"".join(dateList) + "\""

# extract date parsing format from functions string and convert to logstash format
# change date, ref is https://community.rsa.com/docs/DOC-85016 pages 37-38 vs https://www.elastic.co/guide/en/logstash/current/plugins-filters-date.html#plugins-filters-date-match
# for example "10/Oct/2000:13:55:36" is parsed in RSA with "%D/%B/%W:%N:%U:%O" and "dd/MMM/yyyy:HH:mm:ss" in logstash
# def convertDate(s):
#     c = ""
#     eventtime = s.find("EVNTTIME")
#     if eventtime != -1:
#         # extract the date format between the ''
#         a = s.find("'",eventtime)
#         if a != -1:
#             b = s.find("'",a+1)
#             if b>a:
#                 sub = s[a+1:b]
#                 # replace static chars
#                 regex = re.compile("([a-zA-Z]+)")		# just matching a letter
#                 for i in range(0,len(sub)):
#                     if regex.match(sub[i]):
#                         # if first character is a letter, escape it
#                         if i == 0:
#                             c = c + "'" + sub[i] + "'"
#                         else:
#                             # if char not preceded by a %, escape it
#                             if sub[i-1:i] != '%':
#                                 c = c + "'" + sub[i] + "'"
#                             else:
#                                 # otherwise add it
#                                 c = c + sub[i]
#                     else:
#                         # otherwise add it
#                         c = c + sub[i]
#                 # replace the specific chars by their logstash date filter equivalent
#                 c = c.replace("%C", "M/d/yy H:m:s")
#                 c = c.replace("%R", "MMMM")
#                 c = c.replace("%B", "MMM")
#                 c = c.replace("%M", "MM")
#                 c = c.replace("%G", "M")
#                 c = c.replace("%D", "dd")
#                 c = c.replace("%F", "d")
#                 c = c.replace("%H", "HH")
#                 c = c.replace("%I", "HH")
#                 c = c.replace("%N", "H")
#                 c = c.replace("%T", "mm")
#                 c = c.replace("%U", "m")
#                 c = c.replace("%J", "D")
#                 c = c.replace("%P", "a")
#                 c = c.replace("%S", "ss")
#                 c = c.replace("%O", "s")
#                 c = c.replace("%Y", "yy")
#                 c = c.replace("%W", "yyyy")
#                 c = c.replace("%Z", "H:m:s")
#                 c = c.replace("%A", "D")
#                 c = c.replace("%Q", "a")    # AM/PM
#                 c = c.replace("%K", "")    # undocumented... seen in cef.xml
#                 c = c.replace("%L", "")    # undocumented... seen in cef.xml
#                 c = c.replace("%E", "")    # undocumented... seen in v20_trendmicromsg.xml
#                 c = c.replace("%X", "UNIX")
#                 if '%' in c: print("Missing a condition in date conversion: " + c)
#     return c

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
    if s == "": return s
    if config.NO_GROK_ANCHORS:
        return "\"" + str.strip(s.replace("\"","\\\"")) + "\""
    else:
        return "\"^" + str.strip(s.replace("\"","\\\"")) + "$\""

# escaping " in dissect content
def escapeDissect(s):
    if s == "": return s
    return "\"" + str.strip(s.replace("\"","\\\"")) + "\""

# escapes a string in logstash (only escaping ")
def escapeString(s):
    return str.strip(s.replace("\"","\\\""))

# escape special characters in grok :  \ . ^ $ * + - ? ( ) [ ] { } |
def escapeRegex(s):
    # s = str(s,'utf-8')
    s = s.replace("\\", "\\\\"); s = s.replace(".", "\\."); s = s.replace("^", "\\^"); s = s.replace("$", "\\$")
    s = s.replace("*", "\\*"); s = s.replace("+", "\\+"); s = s.replace("-", "\\-"); s = s.replace("?", "\\?")
    s = s.replace("(", "\\("); s = s.replace(")", "\\)"); s = s.replace("[", "\\["); s = s.replace("]", "\\]")
    s = s.replace("{", "\\{"); s = s.replace("}", "\\}"); s = s.replace("|", "\\|")
    s = s.replace(chr(9), "\\t"); s = s.replace(chr(10), "\\n"); s = s.replace(chr(13), "\\r"); s = s.replace(" ", "\\s")
    return s