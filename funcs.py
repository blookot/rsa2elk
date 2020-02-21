#!/usr/bin/env python

########################################################################
# RSA2ELK, by Vincent Maury
# Converts Netwitness log parser configuration to Logstash configuration
# see https://github.com/blookot/rsa2elk
########################################################################

import config
import re
import csv
import sys

# carriage return for logstash conf, just \n for linux
CR = "\n"

# insert n times a tab
def t(n):
    t=""
    for i in range(0,n):
        t=t+"\t"
    return t

# Replace all RSA date syntax with LS date filter one
def convertDate(s):
    dateList = set()
    pattern = re.compile(",'([^']+)'")
    for dStr in pattern.finditer(s):
        c = dStr.group(1)
        # first, replace all non coding (not having a %) chars, like T, cf https://www.elastic.co/guide/en/logstash/current/plugins-filters-date.html#plugins-filters-date-match
        c = re.sub("([^%])([a-zA-Z]+)", r"\1'\2'", c)
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

# remove dots in field names
def removeDots(fldName):
    if "." in fldName:
        return "[" + fldName.replace(".","][") + "]"
    else:
        return fldName

# transform a nested field into a nested es mapping
def generateFieldMapping(fldName, fldType):
    # either key.subkey as RSA format
    if "." in fldName:
        # split on .
        flds = fldName.split(".")
        if len(flds) == 2: config.esMap["mappings"]["properties"][flds[0]]["properties"][flds[1]] = {"type": fldType}
        elif len(flds) == 3: config.esMap["mappings"]["properties"][flds[0]]["properties"][flds[1]]["properties"][flds[2]] = {"type": fldType}
        elif len(flds) == 4: config.esMap["mappings"]["properties"][flds[0]]["properties"][flds[1]]["properties"][flds[2]]["properties"][flds[3]] = {"type": fldType}
        elif len(flds) == 5: config.esMap["mappings"]["properties"][flds[0]]["properties"][flds[1]]["properties"][flds[2]]["properties"][flds[3]]["properties"][flds[4]] = {"type": fldType}
        else:
            print("Error: are you really using more than 5 levels of nested field?")
            sys.exit(-1)
    # or [key][subkey] after mutate
    elif "][" in fldName:
        # split on ][
        flds = fldName[1:-1].split("][")
        if len(flds) == 2: config.esMap["mappings"]["properties"][flds[0]]["properties"][flds[1]] = {"type": fldType}
        elif len(flds) == 3: config.esMap["mappings"]["properties"][flds[0]]["properties"][flds[1]]["properties"][flds[2]] = {"type": fldType}
        elif len(flds) == 4: config.esMap["mappings"]["properties"][flds[0]]["properties"][flds[1]]["properties"][flds[2]]["properties"][flds[3]] = {"type": fldType}
        elif len(flds) == 5: config.esMap["mappings"]["properties"][flds[0]]["properties"][flds[1]]["properties"][flds[2]]["properties"][flds[3]]["properties"][flds[4]] = {"type": fldType}
        else:
            print("Error: are you really using more than 5 levels of nested field?")
            sys.exit(-1)
    # plain key
    else:
        config.esMap["mappings"]["properties"][fldName] = {"type": fldType}

# read table-map and populate dicts
def initMapping():
    noComma = False; noSemiColon = False
    # trying to open table map file with , delimiter first (french way!)
    with open(config.MAPPING_FILE,'r') as csvFile:
        try:
            reader = csv.DictReader(csvFile, delimiter=',')
            for row in reader:
                # if field is flagged as "Transient", we don't take it into consideration
                if row['ecsName'] != "" and row['flags'] != "Transient":
                    config.ecsField[row['envisionName']] = row['ecsName']
                    config.ecsType[row['envisionName']] = row['ecsType']
        except:
            noComma = True
    if noComma:
        with open(config.MAPPING_FILE,'r') as csvFile:
            try:
                reader = csv.DictReader(csvFile, delimiter=';')
                for row in reader:
                    # TODO: not sure what I should do with the fields marked "Transient"
                    if row['ecsName'] != "": # and row['flags'] != "Transient":
                        config.ecsField[row['envisionName']] = row['ecsName']
                        config.ecsType[row['envisionName']] = row['ecsType']
            except:
                noSemiColon = True
    if noComma and noSemiColon:
        print("CSV mapping file expecting ; or , delimiter. Exiting...")
        sys.exit(-1)

# get a possible valuemap func and store the fields
def getValueMap(fld,vmFunc):
    # form is *getEventCategoryActivity(action)
    pattern = re.compile("\*([^\(]+)\(([^\)]+)\)")
    m = pattern.match(vmFunc)
    if m is not None:
        k,v = m.group(1),m.group(2)
        # let's look for the func in the valuemap funcs we've stored
        if k in config.valueMap:
            # record the func parameter as the key
            config.valueMap[k]["fld"] = v
            # record the destination field as well
            config.valueMap[k]["newFld"] = fld
            config.allFields.add(fld)
