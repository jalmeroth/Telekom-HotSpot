#!/usr/bin/python
import re
import os
import sys
import getpass
import keyring
import logging
import argparse
import requests

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from uuid import uuid4


# Return values
#	0 ok
#	1 Could not connect
#	2 Could not check username
#	3 Giving up, retried often


def setKeyring(username, password):
	"""docstring for setKeyring"""
	return keyring.set_password("Telekom_HotSpot", username, password)

def getKeyring(username):
	"""docstring for getKeyring"""
	return keyring.get_password("Telekom_HotSpot", username)

def search_domains():
	"""docstring for search_domains"""
	resolver = "/etc/resolv.conf"
	result = []
	
	if os.path.exists(resolver) and os.access(resolver, os.R_OK):
		f = open(resolver,'r')
		for line in f.readlines():
			if not line.startswith('#'): # leave out comments
				pair = line.split()
				if pair[0] in ('domain', 'search'):
					result = pair[1:]
	return result

def onlinestate():
	"""docstring for onlinestate"""
	logger.info("Determing online state.")
	
	# Sniffed this URL from iOS HotSpot Manager
	url = "http://m.t-mobile.net/topapps/check.html"
	url += "?" + str(uuid4()).upper()
	
	connect_timeout = 10.0
	read_timeout = 10.0
	
	try:
		r = requests.get(url,
			timeout=(connect_timeout, read_timeout),
			allow_redirects=False)
	except Exception as e:
		print "There was an error:", e
		sys.exit(1)
	else:
		logger.debug('Status Code: ' + str(r.status_code))
		return True if r.status_code == 200 else False

def viewstate():
	"""docstring for viewstate"""
	logger.info("Determing view state.")
	
	url = "https://hotspot.t-mobile.net/wlan/start.do"
	r = requests.get(url)
	
	htmlstring = r.text
	pattern= re.compile(r'<input type="hidden" name="javax.faces.ViewState" id="javax.faces.ViewState" value="(.+?)" />')
	matches = pattern.findall(htmlstring)
	
	for match in matches:
		return match

def checkusername(username):
	"""docstring for checkusername"""
	logger.info("Checking username.")
	
	try:
		r = requests.post("https://hotspot.t-mobile.net/wlan/usernamecheck.do", params={"accountname":username})
	except Exception as e:
		print "There was an error:", e
		sys.exit(1)
	else:
		return True if (r.status_code == 200 and r.text == "1") else False

def login(username, password):
	"""docstring for login"""
	logger.info("Logging in.")
	url = "https://hotspot.t-mobile.net/wlan/start.do"
	
	params = {
		"f_login_submit": "Submit",
		"username": username,
		"password": password,
		"roamRealm": "t-mobile.net",
		"terms_conditions": "true",
		"payment_advice": "true",
		"clear_session": "true",
		"f_login_SUBMIT": "1",
		"javax.faces.ViewState": viewstate()
	}
	try:
		r = requests.post(url, data=params)
	except Exception as e:
		print "There was an error:", e
		sys.exit(1)
	else:
		return (r.status_code == requests.codes.ok)

def logout():
	"""docstring for logout"""
	logger.info("Logging out.")
	
	url = "https://hotspot.t-mobile.net/wlan/stop.do"
	
	try:
		r = requests.post(url)
	except Exception as e:
		print "There was an error:", e
		sys.exit(1)
	else:
		print r.text
		return (r.status_code == requests.codes.ok)

def main():
	"""docstring for main"""
	# initialize Arg-parser
	parser = argparse.ArgumentParser()
	
	# setup Arg-parser
	parser.add_argument('-u', '--username', type=str)
	parser.add_argument('-p', '--password', type=str)
	
	# initialize args
	args = sys.argv[1:]

	# parse arguments
	args, unknown = parser.parse_known_args(args)
	logger.debug("args: " + str(args) + " unknown: " + str(unknown))
	
	username = args.username or raw_input('Please enter your username: ')
	
	if username:
		
		password = getKeyring(username)
		
		if not password:
			print "Username:", username
			password = getpass.getpass('Please enter your password: ')

			if username and password:
				setKeyring(username, password)
		
		hotspot_domains = ('railnet.train')
		domains = search_domains()
		
		# connected to HotSpot
		connected = False
		for domain in domains:
			if domain in hotspot_domains:
				logger.info('Search-Domain: Matched')
				connected = True
		
		if connected:
			online = onlinestate()
			retries = 0
		
			while online is False:
				retries += 1
				if checkusername(username):
					success = login(username, password)
					online = onlinestate()
				else:
					return 2
				if retries >= 5:
					return 3
		
			if online:
				print "You're online."
				return 0
			else:
				print "Could not connect."
				return 1
		else:
			logger.info('Search-Domain: Mismatch')
			return 0

if __name__ == '__main__':
	sys.exit(main())