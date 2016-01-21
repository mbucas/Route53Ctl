#!/usr/bin/python
# coding: utf-8
"""
Route53DynUpdate
================

AWS Route53 DNS API dynamic IP update

This program updates the IP address in IPv4 DNS records in AWS using Route53
API.

It runs as a daemon, and verifies periodically if the public IP address of the
current machine has changed. When the address has changed, it calls Route53 API
to set the new address.

The configuration file is by default at /etc/network/Route53DynUpdate.ini

It contains a General section and a section for each hostname to update.

Parameters in General section :
 - AWSAccessKeyId : AWS Access Key Id
 - AWSSecretAccessKey : AWS Secret Access Key
 - Delay : time between checks, in seconds
    Default value 60
 - LogType : File or Syslog
    Default value File
 - LogDestination : if LogType is File, the log file
    Default value /var/log/Route53DynUpdate.log
 - PIDFile : PID file
    Default value /run/Route53DynUpdate.pid
 - PublicIPSource : Website to get the public IP
    Default value http://ip.42.pl/raw
 - UseDNS
    There at least two ways to get IP addresses
    - DNS query : does not work if addresses are overridden locally
    - Route53 API call
    Default value : False
 - RunAsDaemon : Fork twice if True
    Default value : True

Parameters in hostname section :
 - AWSAccessKeyId
 - AWSSecretAccessKey
 - UseDNS
They have the  same function as above, they override the General section.

TODO :
 - Handle CNAME DNS entries and aliases
 - Check the type of the record set
 - Handle more errors
 - Use different AWS credentials for hosts if configured
 - Publish on GitHub

Limits
 - A connection to Route53 is probably not permanent, so we make a new
   connection when we need to change the IP
 - IPv6 is not considered, because IPv6 addresses should be fixed, not
   dynamic, so it shouldn't be necessary

Author : Mickaël Bucas - mbucas@gmail.com

Copyright transferred to Free Software Foundation, Inc.

    (c) Copyright 2014 Free Software Foundation, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

"""

import os
import sys
import signal
import urllib
import socket
import syslog
import argparse
from time import sleep
from datetime import datetime
from ConfigParser import ConfigParser

import route53

# #######################
# Force IPv4 in urllib
origGetAddrInfo = socket.getaddrinfo


# Force family = socket.AF_INET
def getAddrInfoWrapper(host, port, family=0, socktype=0, proto=0, flags=0):
    return origGetAddrInfo(host, port, socket.AF_INET, socktype, proto, flags)

# replace the original socket.getaddrinfo by our version
socket.getaddrinfo = getAddrInfoWrapper
# #######################


defaults = {
    'ConfigFile': '/etc/network/Route53DynUpdate.ini',
    'Delay': 60,
    'LogType': 'File',
    'LogDestination': '/var/log/Route53DynUpdate.log',
    'PIDFile': '/run/Route53DynUpdate.pid',
    'PublicIPSource': 'http://ip.42.pl/raw',
    'UseDNS': 'False',
    'RunAsDaemon': 'True',
    }


class Log(object):
    """ Log messages
        Can log to a file or Syslog
    """

    def __init__(self, logType, logDestination):
        self.logType = logType
        if self.logType == 'File':
            self.file = open(logDestination, 'a')
        elif self.logType == 'Syslog':
            syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_DAEMON)
        else:
            print "Invalid LogType : " + logType
            os._exit(1)

    def log(self, message):
        if self.logType == 'File':
            if self.file:
                t = datetime.now().strftime('%Y-%m-%d %H:%M:%S | ')
                self.file.write(t + message + '\n')
                self.file.flush()
        elif self.logType == 'Syslog':
            syslog.syslog(message)

    def close(self):
        if self.logType == 'File':
            if self.file:
                self.file.close()
                # As we catch signals, there may be concurrency between parts of the daemon
                # To make it clear the file is closed, assign None to it
                self.file = None
        elif self.logType == 'Syslog':
            syslog.closelog()


class Config():
    """ Configuration in a INI file
        Read the configuration from an INI file.

        For the General section, set attributes with values found in the file
        or default values.

        Other sections should be named with the host name. They can have
        specific parameters
    """

    configAttributes = [
        'AWSAccessKeyId', 'AWSSecretAccessKey', 'Delay', 'LogType', 'LogDestination', 'PIDFile',
        'PublicIPSource', 'UseDNS', 'RunAsDaemon',
        ]
    hostAttributes = ['AWSAccessKeyId', 'AWSSecretAccessKey', 'UseDNS', ]

    def __init__(self, configFile):
        self.parser = ConfigParser()
        self.configFile = configFile
        for attribute in self.configAttributes:
            if attribute in defaults:
                setattr(self, attribute, defaults[attribute])
            else:
                setattr(self, attribute, None)
        self.hosts = {}

    def read(self):
        if os.path.isfile(self.configFile):
            self.parser.read(self.configFile)

            if self.parser.has_section('General'):
                for attribute in self.configAttributes:
                    if self.parser.has_option('General', attribute):
                        setattr(self, attribute, self.parser.get('General', attribute))
            for section in self.parser.sections():
                if section != 'General':
                    host = {}
                    for attribute in self.hostAttributes:
                        if self.parser.has_option(section, attribute):
                            host[attribute] = self.parser.get(section, attribute)
                        elif self.parser.has_option('General', attribute):
                            host[attribute] = self.parser.get('General', attribute)
                        elif attribute in defaults:
                            host[attribute] = defaults[attribute]

                    self.hosts[section] = host


class Daemon(object):
    """ Running daemon

        Verifies periodically if the public IP address of the current machine
        has changed. When the address has changed, it calls Route53 API to set
        the new address.

        It automatically reloads configuration if it has changed, based on
        timestamp of the configuration file.

        Assumptions:
         - Only one public IP address
    """

    def __init__(self, configFile):
        self.hosts = {}
        self.configFile = configFile
        self.readConfig(firstTime=True)
        if self.config.RunAsDaemon == 'True':
            self.createDaemon()
        self.initLog()
        self.getAmazonIP()
        # Install signal handlers
        signal.signal(signal.SIGTERM, self.sigTERMhandler)
        signal.signal(signal.SIGINT, self.sigTERMhandler)

    def run(self):
        while True:
            self.readConfig()

            publicIP = self.getPublicIP()

            if publicIP != '':
                change = 0
                for host in self.config.hosts:
                    if publicIP != self.hosts[host]['IP']:
                        change += 1
                if change > 0:
                    self.updateIP(publicIP)

            sleep(self.config.Delay)

    def readConfig(self, firstTime=False):
        try:
            fd = os.open(self.configFile, os.O_RDONLY)
            statConfigFile = os.fstat(fd)
            os.close(fd)
        except OSError, e:
            print 'Configuration file not found ' + self.configFile + ' : ' + e.strerror
            os._exit(1)

        if firstTime:
            self.timestampConfigFile = 0

        if self.timestampConfigFile < statConfigFile.st_mtime:
            self.config = Config(self.configFile)
            self.config.read()
            if self.config.AWSAccessKeyId is None:
                print "AWSAccessKeyId is not set in the configuration file"
                exit(1)
            if self.config.AWSSecretAccessKey is None:
                print "AWSSecretAccessKey is not set in the configuration file"
                exit(1)
            self.timestampConfigFile = statConfigFile.st_mtime

    def initLog(self):
        pid = str(os.getpid())
        f = open(self.config.PIDFile, 'w')
        f.write(pid+'\n')
        f.close()
        self.log = Log(self.config.LogType, self.config.LogDestination)
        self.log.log('Starting with PID='+pid)

    def getRecordSets(self):
        """ Get record sets from Amazon
            We retrieve all record sets whatever their type
        """
        r53 = route53.connect(
            aws_access_key_id=self.config.AWSAccessKeyId,
            aws_secret_access_key=self.config.AWSSecretAccessKey
            )
        r53RecordSets = []
        for zone in r53.list_hosted_zones():
            for record_set in zone.record_sets:
                r53RecordSets.append(record_set)
        return r53RecordSets

    def getAmazonIP(self):
        """ Get the IPv4 address from Amazon

            There at least two ways to get IP addresses
             - DNS query : does not work if addresses are overridden locally
             - Route53 API call
        """
        r53RecordSets = self.getRecordSets()

        for host in self.config.hosts:
            if self.config.hosts[host]['UseDNS'] == 'True':
                self.hosts[host] = {'IP': socket.gethostbyname(host)}
                self.log.log(host + ' IP is ' + self.hosts[host]['IP'])
            else:
                r53Host = None

                # TODO : Check the type of the record set
                for r53RecordSet in r53RecordSets:
                    if r53RecordSet.name == host or r53RecordSet.name == host + '.':
                        r53Host = r53RecordSet
                        break

                if r53Host:
                    self.hosts[host] = {'IP': r53Host.records[0]}
                    self.log.log(host + ' IP is ' + self.hosts[host]['IP'])
                else:
                    self.log.log('Failed to find ' + host)

    def sigTERMhandler(self, signum, frame):
        self.log.log("Caught signal %d" % signum)
        self.closeLog()
        os._exit(0)

    def closeLog(self):
        self.log.log('Ending')
        self.log.close()

    def getPublicIP(self):
        """ Various possibilities
             - Personal site with a PHP file containing <?php echo $_SERVER['REMOTE_ADDR']; ?>
             - http://ip.42.pl/raw
             - http://httpbin.org/ip
             - http://checkip.dyndns.com (needs parsing)
        """
        try:
            publicIP = urllib.urlopen(self.config.PublicIPSource).read()
        except:
            publicIP = ''
        return publicIP

    def updateIP(self, publicIP):
        """ Call Route53 API to update a record
        """
        r53RecordSets = self.getRecordSets()

        for host in self.config.hosts:
            r53Host = None

            # TODO : Check the type of the record set
            for r53RecordSet in r53RecordSets:
                if r53RecordSet.name == host or r53RecordSet.name == host + '.':
                    r53Host = r53RecordSet
                    break

            if r53Host:
                r53Host.records = [publicIP]
                r53Host.save()  # Does the actual call to the API

                self.log.log(host + ' New IP is ' + publicIP)
                self.hosts[host]['IP'] = publicIP
            else:
                self.log.log('Failed to find ' + host)

    def createDaemon(self):
        """ Detach a process from the controlling terminal and run it in the
            background as a daemon.

            http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/278731
        """
        signal.signal(signal.SIGHUP, signal.SIG_IGN)

        try:
            pid = os.fork()
        except OSError, e:
            return((e.errno, e.strerror))	 # ERROR (return a tuple)

        if pid == 0:	   # The first child.
            os.setsid()
            try:
                pid = os.fork()
            except OSError, e:
                return((e.errno, e.strerror))  # ERROR (return a tuple)

            if (pid == 0):	  # The second child.
                os.chdir("/")
            else:
                os._exit(0)	  # Exit parent (the first child) of the second child.
        else:
            os._exit(0)		 # Exit parent of the first child.

        try:
            maxfd = os.sysconf("SC_OPEN_MAX")
        except (AttributeError, ValueError):
            maxfd = 256	   # default maximum

        for fd in range(0, maxfd):
            try:
                os.close(fd)
            except OSError:   # ERROR (ignore)
                pass

        # Redirect the standard file descriptors to /dev/null.
        os.open("/dev/null", os.O_RDONLY)   # standard input (0)
        os.open("/dev/null", os.O_RDWR)     # standard output (1)
        os.open("/dev/null", os.O_RDWR)     # standard error (2)
        return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='configuration file', default=defaults['ConfigFile'])
    args = parser.parse_args()
    daemon = Daemon(args.file)
    daemon.run()

if __name__ == "__main__":
    main()
