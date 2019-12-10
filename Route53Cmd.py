#!/usr/bin/python
# coding: utf-8
"""
Route53Cmd
================

AWS Route53 DNS API command line interface

This program

The configuration file is by default at ~/.Route53Cmd.ini

It contains a General section and a section for each hostname to update.

Parameters in General section :
 - AWSAccessKeyId : AWS Access Key Id
 - AWSSecretAccessKey : AWS Secret Access Key

TODO :
 - Handle more errors


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
import argparse
from configparser import ConfigParser

import boto3


defaults = {
    'ConfigFile': '/etc/network/Route53DynUpdate.ini',
#    'ConfigFile': '~/.Route53Cmd.ini',
    }


class Config():
    """ Configuration in a INI file
        Read the configuration from an INI file.

        For the General section, set attributes with values found in the file
        or default values.
    """

    configAttributes = ['AWSAccessKeyId', 'AWSSecretAccessKey', ]

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


class Command(object):
    """ Command
    """

    def __init__(self, args):
        self.args = args
        self.readConfig()

    def run(self):
        if self.args.action == 'list':
            self.do_list()
        elif self.args.action == 'add':
            self.do_add()
        elif self.args.action == 'delete':
            self.do_delete()
        elif self.args.action == 'listzones':
            self.do_listzones()
        else:
            raise NotImplementedError()

    def readConfig(self):
        if self.args.file is None:
            print("Configuration file is not provided")
            exit(1)
        self.config = Config(self.args.file)
        self.config.read()
        if self.config.AWSAccessKeyId is None:
            print("AWSAccessKeyId is not set in the configuration file")
            exit(1)
        if self.config.AWSSecretAccessKey is None:
            print("AWSSecretAccessKey is not set in the configuration file")
            exit(1)

    def connectRoute53(self):
        self.route53 = boto3.client(
            'route53',
            aws_access_key_id=self.config.AWSAccessKeyId,
            aws_secret_access_key=self.config.AWSSecretAccessKey
        )

    def getHostedZones(self):
        self.hostedZonesInfo = self.route53.list_hosted_zones()
        
    def getRecordSets(self):
        """ Get record sets from Amazon
            We retrieve all record sets whatever their type
        """
        r53RecordSets = []
        self.getHostedZones()
        for zone in self.hostedZonesInfo['HostedZones']:
            moreRecordSets = True
            StartRecordName = ''
            StartRecordType = ''
            while moreRecordSets:
                if StartRecordName == '':
                    self.recordSsetsInfo = self.route53.list_resource_record_sets(
                        HostedZoneId=zone['Id']
                    )
                else:
                    self.recordSsetsInfo = self.route53.list_resource_record_sets(
                        HostedZoneId=zone['Id'],
                        StartRecordName=StartRecordName,
                        StartRecordType=StartRecordType
                    )
                for record_set in self.recordSsetsInfo['ResourceRecordSets']:
                    r53RecordSets.append(record_set)
                moreRecordSets = self.recordSsetsInfo['IsTruncated']
                if moreRecordSets:
                    StartRecordName = self.recordSsetsInfo['NextRecordName']
                    StartRecordType = self.recordSsetsInfo['NextRecordType']
        return r53RecordSets

    def do_list(self):
        self.connectRoute53()
        rs = self.getRecordSets()
        for record in rs:
            if 'TTL' in record:
                ttl = str(record['TTL'])
            else:
                ttl= ''
            if 'ResourceRecords' in record:
                extList = []
                for rec in record['ResourceRecords']:
                    extList.append(rec['Value'])
                ext = ','.join(extList)
            elif 'AliasTarget' in record:
                ext = 'AliasTarget=' + record['AliasTarget']['DNSName']
            else:
                ext = ''
            # name, ttl, class, type, data
            # http://www.zytrax.com/books/dns/ch8/
            recordstr = (
                record['Name'] + (' ' * (40 - len(record['Name'])))
                + ' ' + ttl + (' ' * (6 - len(ttl)))
                + ' IN ' + record['Type'] + (' ' * (6 - len(record['Type']))) + ' '
                + ext
                )
            print(recordstr)

    def do_change(self, action):
        if not self.args.name:
            raise Exception('Missing parameter : host name')
        if not self.args.recordtype:
            raise Exception('Missing parameter : record type')

        self.connectRoute53()
        self.getHostedZones()
        # TODO Possibility to use another zone than the first one
        targetZone = self.hostedZonesInfo['HostedZones'][0]['Id']
        
        resourceValue = ''
        if self.args.recordtype == 'A':
            if not self.args.ip:
                raise Exception('Missing parameter : IPv4 address')
            # TODO : Check IPv4 format
            resourceValue = self.args.ip
        elif self.args.recordtype == 'AAAA':
            if not self.args.ip:
                raise Exception('Missing parameter : IPv6 address')
            # TODO : Check IPv6 format
            resourceValue = self.args.ip
        elif self.args.recordtype == 'CNAME':
            if not self.args.cname:
                raise Exception('Missing parameter : canonical name')
            resourceValue = self.args.cname
        else:
            raise NotImplementedError()

        changes = {
            'Action': action,
            'ResourceRecordSet': {
                'Name': self.args.name,
                'Type': self.args.recordtype,
                'TTL': 300,
                'ResourceRecords' : [{'Value': resourceValue}],
            }
        }
        self.route53.change_resource_record_sets(
            HostedZoneId=targetZone,
            ChangeBatch={'Changes': [changes]}
        )

    def do_add(self):
        self.do_change('CREATE')

    def do_delete(self):
        self.do_change('DELETE')

    def do_listzones(self):
        self.connectRoute53()
        self.getHostedZones()
        for zone in self.hostedZonesInfo['HostedZones']:
            print(zone)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='configuration file', default=defaults['ConfigFile'])
    # TODO 'modify'
    parser.add_argument('-a', '--action', help='action', choices=['list', 'add', 'delete', 'listzones', ], required=True)
    # TODO Other types
    parser.add_argument('-r', '--recordtype', help='record type', choices=['A', 'AAAA', 'CNAME', ])
    parser.add_argument('-n', '--name', help='host name')
    parser.add_argument('-c', '--cname', help='canonical name')
    parser.add_argument('-i', '--ip', help='IPv4 or IPv6 address')

    args = parser.parse_args()
    # NAME should be a fully qualified domain name
    # TODO Allow non-FQDN parameters
    if args.name:
        if not args.name.endswith('.'):
            args.name += '.'
    # CNAME should be a fully qualified domain name
    if args.cname:
        if not args.cname.endswith('.'):
            args.cname += '.'
    command = Command(args)
    command.run()

if __name__ == "__main__":
    main()
