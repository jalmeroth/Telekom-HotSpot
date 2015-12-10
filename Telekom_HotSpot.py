#!/usr/bin/python
import re
import os
import sys
import time
import shlex
import getpass
import keyring
import logging
import argparse
import requests
import threading
import subprocess

logfmt = '%(asctime)s (%(levelname)s) %(message)s'
logging.basicConfig(format=logfmt, level=logging.INFO, filename="run.log")
logger = logging.getLogger(__name__)

from uuid import uuid4
from Cocoa import *
from SystemConfiguration import *


HOTSPOT_NETWORKS = ('Telekom')
HOTSPOT_DOMAINS = ('railnet.train','t-mobile.de')


class ConnectionStatus(object):
    """docstring for ConnectionStatus"""
    def __init__(self, username, password):
        super(ConnectionStatus, self).__init__()
        self.username = username
        self.password = password
    
    def search_domains(self):
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
    
    def onlinestate(self):
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
            logger.debug("There was an error: %s", e)
            print "There was an error:", e
            return False
        else:
            logger.debug('Status Code: ' + str(r.status_code))
            return True if r.status_code == 200 else False
    
    def viewstate(self):
        """docstring for viewstate"""
        logger.info("Determing view state.")
    
        url = "https://hotspot.t-mobile.net/wlan/start.do"
        r = requests.get(url)
    
        htmlstring = r.text
        pattern= re.compile(r'<input type="hidden" name="javax.faces.ViewState" id=".+?" value="(.+?)" />')
        matches = pattern.findall(htmlstring)
        
        logger.debug('viewstate:' + str(matches))
        
        try:
            return matches[0]
        except IndexError as e:
            pass

    def checkusername(self):
        """docstring for checkusername"""
        logger.info("Checking username.")
        
        try:
            r = requests.post("https://hotspot.t-mobile.net/wlan/usernamecheck.do", params={"accountname":self.username})
        except Exception as e:
            logger.debug("There was an error: %s", e)
            print "There was an error:", e
            return False
        else:
            return True if (r.status_code == 200 and r.text == "1") else False

    def login(self):
        """docstring for login"""
        logger.info("Logging in.")
        
        url = "https://hotspot.t-mobile.net/wlan/start.do"
        
        if not self.viewstate():
            logger.debug("No viewstate available.")
        
        params = {
            "f_login_submit": "Submit",
            "username": self.username,
            "password": self.password,
            "roamRealm": "t-mobile.net",
            "terms_conditions": "true",
            "payment_advice": "true",
            "clear_session": "true",
            "f_login_SUBMIT": "1",
            "javax.faces.ViewState": self.viewstate()
        }
        
        try:
            r = requests.post(url, data=params)
        except Exception as e:
            logger.debug("There was an error: %s", e)
            print "There was an error:", e
            return False
        else:
            return (r.status_code == requests.codes.ok)

    def logout(self):
        """docstring for logout"""
        logger.info("Logging out.")
    
        url = "https://hotspot.t-mobile.net/wlan/stop.do"
    
        try:
            r = requests.post(url)
        except Exception as e:
            logger.debug("There was an error: %s", e)
            print "There was an error:", e
            return False
        else:
            print r.text
            return (r.status_code == requests.codes.ok)

    def IPv4_ready(self):
        """docstring for IPv4_ready
        
        # Return values
        #   0 ok
        #   1 Could not connect
        #   2 Could not check username
        #   3 Giving up, retried often
        """
        
        domains = self.search_domains()
        logger.debug("search_domains: %s", domains)

        # connected to HotSpot
        connected = False
        for domain in domains:
            if domain in HOTSPOT_DOMAINS:
                logger.info('Search-Domain: Matched')
                connected = True
        
        if connected:
            online = self.onlinestate()
            retries = 0
        
            while online is False:
                retries += 1
                if self.checkusername():
                    success = self.login()
                    online = self.onlinestate()
                else:
                    logger.debug('Could not check username.')
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

class NetworkStatus(object):
    
    def __init__(self, cs):
        self.loop = None
        self.status = {
            "SSID": self.getairportnetwork(),
            "IPv4": False,
            "IPv6": False
        }
        self.cs = cs
    
    def getairportnetwork(self):
        """docstring for getairportnetwork"""
        data = None
        
        cmd = "/usr/sbin/networksetup -getairportnetwork en0"
        out_data, err_data, ret_code = run_cmd(cmd)
        
        if(ret_code == 0):
            pattern= re.compile(r'Current Wi-Fi Network: (.+)$')
            matches = pattern.findall(out_data)
            
            logger.debug("airportnetworks: %s", matches)
            
            try:
                data = matches[0]
            except IndexError as e:
                pass
        
        return data
    
    def handleNetworkConfigChange(self, store, changedKeys, info = None):
        pool = NSAutoreleasePool.alloc().init()
        for changedKey in changedKeys:
            newState = SCDynamicStoreCopyValue(store, changedKey)
            
            logger.debug(changedKey)
            
            reason = 'Unknown'
            
            # logger.debug(newState)
            
            # "State:/Network/.*/IPv6"
            IPv6 = re.match(r"State:/Network/(.*)/IPv6", changedKey)
            if IPv6:
                reason = "IPv6:"
                
                if "State:/Network/Global/IPv6" == changedKey:
                    reason += " GLOBAL"
                    self.connection_callback('IPv6', True if newState else False)
                else:
                    reason += " " + IPv6.group(1)
                
                if newState:
                    reason += " up."
                    if 'PrimaryInterface' in newState:
                        reason += ' Interface:' + newState['PrimaryInterface']
                    
                    if 'Router' in newState:
                        reason += ' Router:' + newState['Router']
                else:
                    reason += " down."
            
            # "State:/Network/.*/IPv4"
            IPv4 = re.match(r"State:/Network/(.*)/IPv4", changedKey)
            if IPv4:
                reason = "IPv4:"
                
                if "State:/Network/Global/IPv4" == changedKey:
                    reason += " GLOBAL"
                    self.connection_callback('IPv4', True if newState else False)
                else:
                    reason += " " + IPv4.group(1)
                
                if newState:
                    reason += " up."
                    if 'PrimaryInterface' in newState:
                        reason += ' Interface:' + newState['PrimaryInterface']
                    
                    if 'Router' in newState:
                        reason += ' Router:' + newState['Router']
                else:
                    reason += " down."
            
            # "State:/Network/Interface/.*/AirPort"
            AirPort = re.match(r"State:/Network/Interface/(.*)/AirPort", changedKey)
            if AirPort:
                reason = 'Airport: ' + AirPort.group(1)
                
                if newState and 'Power Status' in newState:
                    reason += ' active.' if newState['Power Status'] == 1 else ' inactive.'
                    if 'CHANNEL' in newState:
                        reason += " Channel: " + str(newState['CHANNEL'])
                    
                    if 'SSID_STR' in newState:
                        reason += " SSID: " + newState['SSID_STR']
                        self.connection_callback('SSID', newState['SSID_STR'])
                    else:
                        logger.debug('Resetting SSID')
                        self.connection_callback('SSID', '')
                else:
                    reason += " inactive."
            
            # "State:/Network/Interface/.*/Link"
            Link = re.match(r"State:/Network/Interface/(.*)/Link", changedKey)
            if Link:
                reason = "Link: " + Link.group(1)
                
                if newState and 'Active' in newState:
                    reason += ' up.' if newState['Active'] == 1 else ' down.'
                else:
                    reason += " down."
            
            logger.debug(reason)
        del pool

    def connection_callback(self, key, val):
        
        if self.status[key] != val: #status has changed
            self.status[key] = val
            
            if key == "SSID": # On network change, reset connection status
                logger.debug('On network change, reset connection status')
                self.status['IPv4'] = False
                self.status['IPv6'] = False
            
            logger.info(self.status)
            
            if self.status['SSID'] in HOTSPOT_NETWORKS:
                
                if self.status['IPv4'] and key == 'IPv4':
                    logger.debug('IPv4 connection ready.')
                    print 'IPv4 connection ready.'
                    cs_thread = threading.Thread(target = self.cs.IPv4_ready)
                    cs_thread.start()
                    
                elif self.status['IPv6'] and key == 'IPv6':
                    logger.debug('IPv6 connection ready.')
                    print 'IPv6 connection ready.'

    def register(self):
        logger.info("Registering listener for network changes.")
        
        pool = NSAutoreleasePool.alloc().init()
        store = SCDynamicStoreCreate(None, "hotspot-supplicant-" + str(time.time()), self.handleNetworkConfigChange, None)
        keys = [
            "State:/Network/Interface/.*/AirPort",
            "State:/Network/Interface/.*/Link",
            "State:/Network/.*/IPv4",
            "State:/Network/.*/IPv6", ]
        SCDynamicStoreSetNotificationKeys(store, None, keys)
        
        # determine as-is status
        as_is = SCDynamicStoreCopyMultiple(store, None, keys)
        self.handleNetworkConfigChange(store, as_is)
        
        source = SCDynamicStoreCreateRunLoopSource(None, store, 0)
        self.loop = CFRunLoopGetCurrent()
        CFRunLoopAddSource(self.loop, source, kCFRunLoopCommonModes)
        CFRunLoopRun()
        del pool
        
    def destroy(self):
        """docstring for destroy"""
        CFRunLoopStop(self.loop)

def run_cmd(cmd):
    """docstring for run_cmd"""
    logger.debug('Running command: %s', cmd)
    
    out_data = err_data = None
    ret_code = -1
    
    try:
        p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out_data, err_data = p.communicate()
    except Exception as e:
        logger.debug(e)
    else:
        ret_code = p.returncode
    finally:
        return (out_data, err_data, ret_code)
        
def setKeyring(username, password):
    """docstring for setKeyring"""
    return keyring.set_password("Telekom_HotSpot", username, password)

def getKeyring(username):
    """docstring for getKeyring"""
    logger.debug('Trying to get password from Keychain.')
    return keyring.get_password("Telekom_HotSpot", username)

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
                logger.info('Storing credentials to keyring.')
                setKeyring(username, password)
        
        cs = ConnectionStatus(username, password)
        ns = NetworkStatus(cs)
        
        monitor_thread = threading.Thread(target = ns.register)
        monitor_thread.start()
        
        try:
            while monitor_thread.is_alive():
                monitor_thread.join(timeout=1.0)
        except (KeyboardInterrupt, SystemExit):
            print "Exiting."
            ns.destroy()
        
if __name__ == '__main__':
    main()