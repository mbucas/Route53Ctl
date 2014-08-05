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
from ConfigParser import ConfigParser

import route53
from route53 import resource_record_set


defaults = {
    'ConfigFile': '~/.Route53Cmd.ini',
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
        else:
            raise NotImplementedError()

    def readConfig(self):
        self.config = Config(self.args.file)
        self.config.read()

    def connectRoute53(self):
        self.r53 = route53.connect(
            aws_access_key_id=self.config.AWSAccessKeyId,
            aws_secret_access_key=self.config.AWSSecretAccessKey
            )

    def getRecordSets(self):
        """ Get record sets from Amazon
            We retrieve all record sets whatever their type
        """
        self.connectRoute53()
        r53RecordSets = []
        for zone in self.r53.list_hosted_zones():
            for record_set in zone.record_sets:
                record_set.record_type = record_set.__class__.__name__.replace('ResourceRecordSet', '')
                r53RecordSets.append(record_set)
        return r53RecordSets

    def do_list(self):
        rs = self.getRecordSets()
        for record in rs:
            ttl = str(record.ttl) if record.ttl else ''
            ext = ','.join(record.records) if record.records else ''
            # name, ttl, class, type, data
            # http://www.zytrax.com/books/dns/ch8/
            recordstr = (
                record.name + (' ' * (40 - len(record.name)))
                + ' ' + ttl + (' ' * (6 - len(ttl)))
                + ' IN ' + record.record_type + (' ' * (6 - len(record.record_type))) + ' '
                + ext
                )
            print recordstr

    def do_add(self):
        if not self.args.name:
            raise Exception('Missing parameter : host name')
        if not self.args.recordtype:
            raise Exception('Missing parameter : record type')

        self.connectRoute53()
        zones = self.r53.list_hosted_zones()
        # TODO Possibility to use another zone than the first one
        targetZone = next(zones)
        new_record = None
        if self.args.recordtype == 'A':
            if not self.args.ip:
                raise Exception('Missing parameter : IPv4 address')
            # TODO : Check IPv4 format
            new_record, change_info = targetZone.create_a_record(
                name=self.args.name,
                values=[self.args.ip],
                ttl=300
                )
        elif self.args.recordtype == 'AAAA':
            if not self.args.ip:
                raise Exception('Missing parameter : IPv6 address')
            # TODO : Check IPv6 format
            new_record, change_info = targetZone.create_aaaa_record(
                name=self.args.name,
                values=[self.args.ip],
                ttl=300
                )
        elif self.args.recordtype == 'CNAME':
            if not self.args.cname:
                raise Exception('Missing parameter : canonical name')
            new_record, change_info = targetZone.create_cname_record(
                name=self.args.name,
                values=[self.args.cname],
                ttl=300
                )
        else:
            raise NotImplementedError()

        if new_record:
            new_record.save()

    def do_delete(self):
        if not self.args.name:
            raise Exception('Missing parameter : host name')
        if not self.args.recordtype:
            raise Exception('Missing parameter : record type')

        rs = self.getRecordSets()
        deleted = 0
        for record in rs:
            if record.name == self.args.name and record.record_type == self.args.recordtype:
                record.delete()
                deleted += 1

        if deleted == 0:
            raise Exception('Failed to find ' + self.args.name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='configuration file', default=defaults['ConfigFile'])
    # TODO 'modify'
    parser.add_argument('-a', '--action', help='action', choices=['list', 'add', 'delete', ], required=True)
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
