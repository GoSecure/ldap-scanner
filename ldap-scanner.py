#!/usr/bin/env python
####################
#
# Copyright (c) 2020 Romain Carnus / GoSecure (@romcar)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Checks remotely LDAP signature requirement options
#
# Author:
#  Romain Carnus (@romcar)
#
####################
import sys
import logging
import argparse
import codecs
import calendar
import struct
import time
from impacket import version
from impacket.examples.logger import ImpacketFormatter
from impacket import ntlm
from impacket.ldap import ldap
from impacket.ntlm import NTLMAuthNegotiate,AV_PAIRS, NTLMSSP_AV_TIME, NTLMSSP_AV_FLAGS, NTOWFv2, NTLMSSP_AV_TARGET_NAME, NTLMSSP_AV_HOSTNAME,USE_NTLMv2, hmac_md5

class checker(object):
    def __init__(self, username='', password='', domain='', port=None,
                 hashes=None):

        self.__username = username
        self.__password = password
        self.__port = port #not used for now
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

           
    def check(self, remote_host):
        try:
            ldapclient = ldap.LDAPConnection('ldap://%s' % remote_host)
        except:
            return
        
        try:
            #Default login method does not request for signature, allowing us to check auth result
            ldapclient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            logging.info('LDAP signature not required on target %s (authentication was accepted)', remote_host)
        except ldap.LDAPSessionError as exc:
            if 'strongerAuthRequired:' in str(exc):
                logging.info('LDAP signature was required on target %s (authentication was rejected)', remote_host)
            else:
                logging.warning('Unexpected Exception while authenticating to %s: %s', remote_host, exc)

        ldapclient.close()


# Process command-line arguments.
def main():
    # Init the example's logger theme
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ImpacketFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    logging.info('LDAP security scanner by @romcar / GoSecure - Based on impacket by SecureAuth')

    parser = argparse.ArgumentParser(description="LDAP scanner - Connects over LDAP, attempts to authenticate without signing capabilities.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    group = parser.add_argument_group('connection')

    group.add_argument('-target-file',
                       action='store',
                       metavar="file",
                       help='Use the targets in the specified file instead of the one on'\
                            ' the command line (you must still specify something as target name)')

    """
    #Not supported for now as impacket's ldap client does not allow to specify the port number
    group.add_argument('-port', choices=['389'], nargs='?', default='389', metavar="destination port",
                       help='Destination port to connect to LDAP Server')
    """

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, remote_name = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username == '':
        logging.error("Please supply a username/password (you can't use this scanner with anonymous authentication)")
        return

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    remote_names = []
    if options.target_file is not None:
        with open(options.target_file, 'r') as inf:
            for line in inf:
                remote_names.append(line.strip())
    else:
        remote_names.append(remote_name)

    lookup = checker(username, password, domain, 389, options.hashes)
    for remote_name in remote_names:
        try:
            lookup.check(remote_name)
        except KeyboardInterrupt:
            break


if __name__ == '__main__':
    main()
