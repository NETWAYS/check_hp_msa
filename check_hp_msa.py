#!/usr/bin/env python
"""
Icinga check plugin for HP MSA storages

TODO

---

Copyright (C) 2021 NETWAYS GmbH <info@netways.de>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import os
import sys
import argparse
import logging
import requests
import hashlib
from xml.etree import ElementTree
from urllib.parse import urljoin


VERSION = '0.1.0'

OK       = 0
WARNING  = 1
CRITICAL = 2
UNKNOWN  = 3

STATES = {
    OK: "OK",
    WARNING: "WARNING",
    CRITICAL: "CRITICAL",
    UNKNOWN: "UNKNOWN",
}


class CriticalException(Exception):
    """
    Provide an exception that will cause the check to exit critically with an error
    """

    pass


class Client:
    """
    Simple API client for MSA WBI
    """

    API_PREFIX = '/api/'


    def __init__(self, api, username, password, logger=None, insecure=False):
        self.api = api
        self.username = username
        self.password = password

        self.session = requests.Session()
        self.session_key = None

        self.insecure = insecure

        # TODO: allow debug output
        #self.debug_outdir = 'tmp/'
        self.debug_outdir = None

        if insecure:
            self.session.verify = not insecure

            import urllib3
            urllib3.disable_warnings()

        if logger is None:
            logger = logging.getLogger()

        self.logger = logger


    def credential_hash(self):
        """
        Build a MD5 hashed credential built from username_password
        """
        cred = "%s_%s" % (self.username, self.password)

        return hashlib.md5(cred.encode()).hexdigest()


    def login(self):
        try:
            cred = self.credential_hash()
            xml, response = self.request('login/'+cred)

            responseType, responseText = self.get_response_status(xml)

            # TODO: we either receive sessionkey in responseText or a cookie in newer API releases
            # both should be supported
            self.session_key = responseText

        except Exception as e:
            raise CriticalException('login failed: ' + str(e))


    def get_response_status(self, xml):
        """
        Parse and return status information from the XML response

        Will raise an Exception when not successful
        """

        status = xml.find("./OBJECT[@name='status']")
        responseType = status.find("./PROPERTY[@name='response-type']").text
        responseText = status.find("./PROPERTY[@name='response']").text

        self.logger.debug('XML response: %s - %s' % (responseType, responseText))

        if responseType != "Success":
            raise Exception("%s: %s" % (responseType, responseText))

        return responseType, responseText


    def request(self, url, method='GET', **kwargs):
        """
        Basic XML API request handling

        Returns the XML result when successful
        """

        base_url = urljoin(self.api, self.API_PREFIX)
        request_url = urljoin(base_url, url)

        self.logger.debug("starting API %s request from: %s", method, url)

        try:
            headers = {}

            if self.session_key:
                headers['sessionKey'] = self.session_key

            response = self.session.request(method, request_url, headers=headers)
        except requests.exceptions.RequestException as e:
            raise CriticalException(e)

        if response.status_code != 200:
            raise CriticalException('Request to %s was not successful: %s' % (request_url, response.status_code))

        try:
            # debug:
            # print(response.text)
            return ElementTree.fromstring(response.text), response
        except Exception as e:
            raise CriticalException('Could not decode API XML: ' + str(e))


    def get_component(self, class_type, name, api_type):
        """
        GET and initialize a class with a certain type
        """
        xml, response = self.request('show/' + name)
        status = self.get_response_status(xml)

        objects = []

        for child in xml:
            if child.tag != 'OBJECT':
                continue

            base_type = child.attrib['basetype']
            if base_type == 'status':
                continue

            assert base_type == api_type

            objects.append(ApiObject(child))

        # TODO: debug response in file
        if self.debug_outdir is not None:
            if not os.path.isdir(self.debug_outdir):
                os.mkdir(self.debug_outdir)

            with open(os.path.join(self.debug_outdir, "show-%s.xml" % name), 'w') as fh:
                fh.write(response.text)

        return class_type(objects)


class ApiObject:
    def __init__(self, element):
        """
        Build a Python object from an XML API object element

        :type element: ElementTree.Element
        """
        assert element.tag == 'OBJECT'

        attrib = element.attrib

        self.name = attrib['name']
        self.base_type = attrib['basetype']
        self.oid = attrib['oid']
        self.properties = {}

        # store all properties in a dict
        for child in element:
            if child.tag != 'PROPERTY':
                continue

            # TODO: display-name might be interesting at some point

            value = child.text
            value_type = child.attrib['type']

            # cast to numeric when API passes that type
            if value_type.startswith('int') or value_type.startswith('uint'):
                value = int(value)

            self.properties[child.attrib['name']] = value


class CheckResult:
    def __init__(self):
        self.state = -1
        self.summary = []
        self.output = []
        self.perfdata = []

    def build_output(self):
        raise NotImplemented("build_output not implemented in %s" % type(self))

    def get_output(self):
        if len(self.summary) == 0:
            self.build_output()
        if self.state < 0:
            self.build_status()

        output = ' - '.join(self.summary)
        if len(self.output) > 0:
            output += "\n\n" + "\n".join(self.output)
        if len(self.perfdata) > 0:
            output += "\n| " + " ".join(self.perfdata)

        try:
            state = STATES[self.state]
        except KeyError:
            state = "UNKNOWN"

        return "[%s] " % state + output

    def build_status(self):
        raise NotImplemented("build_status not implemented in %s" % type(self))

    def get_status(self):
        if self.state < 0:
            self.build_status()
        if self.state < 0:
            return UNKNOWN

        return self.state

    def print_and_return(self):
        print(self.get_output())
        return self.get_status()


class Disks(CheckResult):
    """
    See API Documentation: TODO
    """

    def __init__(self, objects):
        super().__init__()
        self.objects = objects

    def build_output(self):
        states = {
            'disks': 0,
            'unhealthy': 0,
        }

        for disk in self.objects:
            p = disk.properties

            states['disks'] += 1

            # States
            if p['health'] != "OK" or p['error'] != 0:
                states['unhealthy'] += 1

            # Build health summary
            health = p['health']
            if p['health-reason']:
                health += " (%s)" % p['health-reason']
            if p['health-recommendation']:
                health += " (%s)" % p['health-recommendation']
            if p['error'] != 0:
                health += " (error flag)"
            if p['temperature-status'] != 'OK':
                health += " - temperature %s %s" % (p['temperature-status'], p['temperature'])

            self.output.append("[%s] %s %s %s %s %s %s" % (
                p['location'].ljust(4, ' '),
                p['vendor'],
                p['model'],
                p['size'],
                p['serial-number'],
                p['status'],
                health,
            ))

            label = p['location'].replace('.', '_')

            self.perfdata.append("disk_%s_temperature=%s" % (label, p['temperature-numeric']))

        for state in states:
            if states[state] != 0:
                self.summary.append("%d %s" % (states[state], state))

        if len(self.summary) == 0:
            self.summary = ["no disks"]


    def build_status(self):
        states = []

        for disk in self.objects:
            p = disk.properties

            if p['health'] != "OK" or p['error'] != 0:
                states.append(CRITICAL)
            elif p['temperature-status'] != 'OK':
                states.append(WARNING)
            else:
                states.append(OK)


        if len(states) == 0:
            # no disks
            self.state = OK
        else:
            self.state = worst_state(*states)


def worst_state(*states):
    overall = -1

    for state in states:
        if state == CRITICAL:
            overall = CRITICAL
        elif state == UNKNOWN:
            if overall != CRITICAL:
                overall = UNKNOWN
        elif state > overall:
            overall = state

    if overall < 0 or overall > 3:
        overall = UNKNOWN

    return overall


def parse_args():
    args = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)

    args.add_argument('--api', '-A', required=True,
        help='HP MSA host url (e.g. https://msa1.local)')

    args.add_argument('--username', '-u', help='Username for login', required=True)
    args.add_argument('--password', '-p', help='Password for login', required=True)

    args.add_argument('--mode', '-m', help='Check mode', required=True)

    args.add_argument('--insecure', help='Do not check certificates', action='store_true')

    args.add_argument('--version', '-V', help='Print version', action='store_true')

    return args.parse_args()


def main():
    args = parse_args()

    if args.version:
        print("check_hp_msa version %s" % VERSION)
        return 0

    client = Client(args.api, args.username, args.password, insecure=args.insecure)

    client.login()

    mode = None

    if args.mode == 'disks':
        mode = client.get_component(Disks, "disks", "drives")
    else:
        print("[UNKNOWN] unknown mode %s" % args.mode)
        return UNKNOWN

    return mode.print_and_return()


if __package__ == '__main__' or __package__ is None:
    try:
        sys.exit(main())
    except CriticalException as e:
        print("[CRITICAL] " + str(e))
        sys.exit(CRITICAL)
    except Exception:
        exception = sys.exc_info()
        print("[UNKNOWN] Unexpected Python error: %s %s" % (exception[0], exception[1]))

        try:
            import traceback
            traceback.print_tb(exception[2])
        except:
            pass

        sys.exit(UNKNOWN)
