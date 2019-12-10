Route53Ctl
==========

This project contains two programs to work with Amazon Route53 API :
 - A command line interface to add or remove DNS entries (A, AAAA and CNAME are 
 supported)
 - A daemon to dynamically update the IP address for a DNS entry, as a 
 replacement of services like dyn.com or noip.com

It's written in Python 3 using Boto3 and has been tested on Gentoo.
