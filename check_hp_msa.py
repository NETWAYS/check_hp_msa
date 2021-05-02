#!/usr/bin/env python3
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

def getPct(usage, size):
    return round((100/float(size) * float(usage)),2)


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
        self.debug_outdir = 'tmp/'
        #self.debug_outdir = None

        if insecure:
            self.session.verify = not insecure

            import urllib3
            requests.packages.urllib3.disable_warnings()
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

    def get_component(self, name, api_type, outputList, perfDataList=None):
        """
        GET and initialize a class with a certain type
        """
        xml, response = self.request('show/' + name)
        status = self.get_response_status(xml)

        # TODO: debug response in file
        if self.debug_outdir is not None:
            if not os.path.isdir(self.debug_outdir):
                os.mkdir(self.debug_outdir)

            with open(os.path.join(self.debug_outdir, "show-%s.xml" % name), 'w') as fh:
                fh.write(response.text)

        objects = []

        for child in xml:
            if child.tag != 'OBJECT':
                continue

            base_type = child.attrib['basetype']
            if base_type == 'status':
                continue

            objects.append(ApiObject(child))



        return CheckResult(objects,name, outputList, perfDataList)

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
    def __init__(self, objects, objectName, outputList, perfDataList=None):
        super().__init__()
        self.objects = objects
        self.state = -1
        self.summary = []
        self.output = []
        self.perfdata = []
        self.objectName = objectName
        self.outputList = outputList
        self.perfDataList = perfDataList

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

    def get_status(self):
        if self.state < 0:
            self.build_status()
        if self.state < 0:
            return UNKNOWN

        return self.state

    def print_and_return(self):
        print(self.get_output())
        return self.get_status()

    def build_output(self):
        states = {
            'objectctn': 0,
            'unhealthy': 0,
        }

        for obj in self.objects:
            p = obj.properties

            states['objectctn'] += 1

            # States
            if p['health'] != "OK":
                states['unhealthy'] += 1

            # Build health summary
            health = p['health']
            if p['health-reason']:
                health += " (%s)" % p['health-reason']
            if p['health-recommendation']:
                health += " (%s)" % p['health-recommendation']
            
            # Handling output
            outputLine=f"[{health}]" 
            for output in self.outputList:
                outputLine+=f" {p[output]}"
            self.output.append(outputLine)
           
            # Handling PerfData
            if self.perfDataList is not None:   
                for perfDataLine in self.perfDataList:
                    if isinstance(perfDataLine, str):
                        self.perfdata.append(f"{self.objectName}_{perfDataLine}={p[perfDataLine]}")
                    elif isinstance(perfDataLine, list):
                        usage=perfDataLine[0]
                        total=perfDataLine[1]
                        name=perfDataLine[2]
                        pct=getPct(p[usage],p[total])
                        self.perfdata.append(f"{self.objectName}_pct_{name}={pct}")
                    else:
                        raise NotImplemented("handling performance data of type {type(perfDataLine)} is not implemented")

        for state in states:
            if states[state] != 0:
                self.summary.append("%d %s" % (states[state], str(self.objectName)))

        if len(self.summary) == 0:
            self.summary = [f"no {objectName}"]

    def build_status(self):
        states = []

        for obj in self.objects:
            p = obj.properties

            if p['health'] != "OK":
                states.append(CRITICAL)
            else:
                states.append(OK)


        if len(states) == 0:
            # no disks
            self.state = OK
        else:
            self.state = worst_state(*states)

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
        output=['location','vendor','model','size','serial-number','status']
        mode = client.get_component( "disks", "drives",output)

    elif args.mode == 'volumes': 
        output=['volume-name','volume-type','capabilities','size','serial-number']
        perfdata=[
            ['allocated-size-numeric','total-size-numeric','allocation'],
            'allocated-size'
        ]
        mode = client.get_component("volumes","volumes",output,perfdata)

    elif args.mode == 'enclosures':
        output=['durable-id','type','board-model','slots','status']
        perfdata=[
            ['number-of-disks','slots','diskallocation']
        ]
        mode = client.get_component("enclosures", "enclosures",output,perfdata)

    elif args.mode == 'ports':
        output=['port','port-type','media','actual-speed','status']
        perfdata=[
            ['configured-speed-numeric','actual-speed-numeric','speedallocation']
        ]
        mode = client.get_component("ports", "port",output,perfdata)   

    elif args.mode == 'fans':
        output=['name','location','status-ses','status']
        perfdata=[
            'speed'
        ]
        mode = client.get_component("fans", "fan-details",output,perfdata)   
    
    elif args.mode == 'controllers':
        output=['durable-id','ip-address','disks','description','status']
        mode = client.get_component("controllers", "controllers",output)   
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
