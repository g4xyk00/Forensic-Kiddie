#!/usr/bin/python
# Usage: python wse_beautifier.py
# Author: g4xyk00

import sys
import re
import os

#Display Configuration
os.system('color F0')

filePath = sys.argv[1]
file = open(filePath)
eventID = []
scanEventID = ['4624', '4647', '4648', '4688', '4798', '4799']

eventDesc = {
	'4624' : "Logon: An account was successfully logged on",
	'4647' : "User initiated logoff",
	'4648' : "Logon: A logon was attempted using explicit credentials",
	'4688' : "A new process has been created",
	'4798' : "A user's local group membership was enumerated",
	'4799' : "A security-enabled local group membership was enumerated"
}

taskCategory = {
	'12544' : "Logon",
	'12545' : "Logoff",
	'13312' : "Process Creation",
	'13824' : "User Account Management",
	'13826' : "Security Group Management"
}

regexDict = {
	'time': "SystemTime='([0-9A-Z-:.]*)",
	'computer': "<Computer[^>]*>(.*)</Computer>",
	'TargetDomainName':"TargetDomainName[\'](.*)",
	'TargetUserName':"TargetUserName[\'](.*)",
	'ProcessName' : "'ProcessName[\'](.*)",
	'LogonType' : "'LogonType[\'](.*)",
	'NewProcessName' : "'NewProcessName[\'](.*)",
	'SubjectUserName':"SubjectUserName[\'](.*)",
	'CallerProcessName':"CallerProcessName[\'](.*)"
}

#https://www.sans.org/reading-room/whitepapers/forensics/windows-logon-forensics-34132
logonType = {
	'0' : "",
	'2' : "Interactive",
	'3' : "Network",
	'4' : "Batch",
	'5' : "Service",
	'7' : "Unlock",
	'8' : "NetworkCleartext",
	'9' : "NewCredentials",
	'10' : "RemoteInteractive",
	'11' : "CachedInteractive"
}

def getRegexValue(line, regex):
	value = re.search(regex, line)
	if value is not None:
		match = value.group(1)
		return match

def enhanceRegexValue(value):
	indexData = value.find('</Data>')
	return value[1:indexData]

def displayDetail(eid, line):
	time = getRegexValue(line, regexDict['time'])
	computer = getRegexValue(line, regexDict['computer'])

	if eid == "4624" : #logon
		domain = enhanceRegexValue(getRegexValue(line, regexDict['TargetDomainName']))
		user = enhanceRegexValue(getRegexValue(line, regexDict['TargetUserName']))
		process = enhanceRegexValue(getRegexValue(line, regexDict['ProcessName']))
		logon = enhanceRegexValue(getRegexValue(line, regexDict['LogonType']))
		print "%-35s%-20s%-20s%-30s%-20s%-40s" % (time, computer, domain, user, logonType[logon], process)
	elif eid == "4647": #logoff
		domain = enhanceRegexValue(getRegexValue(line, regexDict['TargetDomainName']))
		user = enhanceRegexValue(getRegexValue(line, regexDict['TargetUserName']))
		print "%-35s%-20s%-20s%-30s" % (time, computer, domain, user)
	elif eid == "4648" : #logon
		domain = enhanceRegexValue(getRegexValue(line, regexDict['TargetDomainName']))
		user = enhanceRegexValue(getRegexValue(line, regexDict['TargetUserName']))
		process = enhanceRegexValue(getRegexValue(line, regexDict['ProcessName']))
		print "%-35s%-20s%-20s%-30s%-40s" % (time, computer, domain, user, process)
	elif eid == "4688" : #new process
		process = enhanceRegexValue(getRegexValue(line, regexDict['NewProcessName']))
		print "%-35s%-20s%-40s" % (time, computer, process)
	elif eid == "4798" or eid == "4799": #enumeration
		target = enhanceRegexValue(getRegexValue(line, regexDict['TargetUserName']))
		subject = enhanceRegexValue(getRegexValue(line, regexDict['SubjectUserName']))
		process = enhanceRegexValue(getRegexValue(line, regexDict['CallerProcessName']))
		print "%-35s%-20s%-20s%-20s%-40s" % (time, computer, subject, target, process)

print "="*155
print " __    __ _           _                     __                      _ _             __                 _       ___                  _   _  __ _           "
print "/ / /\ \ (_)_ __   __| | _____      _____  / _\ ___  ___ _   _ _ __(_) |_ _   _    /__\_   _____ _ __ | |_    / __\ ___  __ _ _   _| |_(_)/ _(_) ___ _ __ "
print "\ \/  \/ / | '_ \ / _` |/ _ \ \ /\ / / __| \ \ / _ \/ __| | | | '__| | __| | | |  /_\ \ \ / / _ \ '_ \| __|  /__\/// _ \/ _` | | | | __| | |_| |/ _ \ '__|"
print " \  /\  /| | | | | (_| | (_) \ V  V /\__ \ _\ \  __/ (__| |_| | |  | | |_| |_| | //__  \ V /  __/ | | | |_  / \/  \  __/ (_| | |_| | |_| |  _| |  __/ |   "
print "  \/  \/ |_|_| |_|\__,_|\___/ \_/\_/ |___/ \__/\___|\___|\__,_|_|  |_|\__|\__, | \__/   \_/ \___|_| |_|\__| \_____/\___|\__,_|\__,_|\__|_|_| |_|\___|_|   "
print ""
print "                                                   Windows Security Event Beautifier by Axcel Security"
print "="*155
print ""
print "Prerequisite: wevtutil qe Security > event.xml "
print "Usage: python wse_beautifier.py event.xml\n\n\n"
		
for line in file:
	# To collect a list of unique event ID
	regex = '<EventID[^>]*>([0-9]*)'
	value = re.search(regex, line)
	if value is not None:
		match = value.group(1)
		if match not in eventID:
			eventID.append(match)
			file = open(match + ".txt","w") 
		else:
			file = open(match + ".txt","a") 
		
		file.write(line) 

for eid in scanEventID:
	try:
		eventLog = open(eid + ".txt")

		print "*"*150
		print "Event ID: " + eid + " [" + eventDesc[eid] + "]\n"

		if eid == "4624":
			print "%-35s%-20s%-20s%-30s%-20s%-40s" % ("Time", "Computer", "Domain", "User", "Logon", "Process")
			print "%-35s%-20s%-20s%-30s%-20s%-40s" % ("----", "--------", "------", "----", "-----", "-------")

		elif eid == "4647":
			print "%-35s%-20s%-20s%-30s" % ("Time", "Computer", "Domain", "User")
			print "%-35s%-20s%-20s%-30s" % ("----", "--------", "------", "----")
		
		elif eid == "4648":
			print "%-35s%-20s%-20s%-30s%-40s" % ("Time", "Computer", "Domain", "User", "Process")
			print "%-35s%-20s%-20s%-30s%-40s" % ("----", "--------", "------", "----", "-------")
		
		elif eid == "4688":
			print "%-35s%-20s%-40s" % ("Time", "Computer", "Process")
			print "%-35s%-20s%-40s" % ("----", "--------", "-------")

		elif eid == "4798" or eid == "4799":
			print "%-35s%-20s%-20s%-20s%-40s" % ("Time", "Computer", "Subject", "Target", "Process")
			print "%-35s%-20s%-20s%-20s%-40s" % ("----", "--------", "-------", "------", "-------")
		
		for line in eventLog:
			displayDetail(eid, line)

		print "\n\n"
	except:
		pass
		