#!/usr/bin/env python3

import unittest
import unittest.mock as mock
import sys

sys.path.append('..')

from check_hp_msa import commandline
from check_hp_msa import worst_state
from check_hp_msa import Client
from check_hp_msa import Disks
from check_hp_msa import CriticalException


class MockRequest():
    def __init__(self, status_code, content):
        self.status_code = status_code
        self.text = content


class UtilTesting(unittest.TestCase):

    def test_worst_state(self):
        actual = worst_state(0,1,2,3)
        expected = 2
        self.assertEqual(actual, expected)

        actual = worst_state(-10,0,10)
        expected = 3
        self.assertEqual(actual, expected)

class CLITesting(unittest.TestCase):

    def test_commandline(self):
        actual = commandline(['-A', 'http://localhost', '-u', 'foo', '-p', 'bar', '-m', 'disks', '--auth-hash-type', 'md5'])
        self.assertEqual(actual.api, 'http://localhost')
        self.assertEqual(actual.auth_hash_type, 'md5')

class ClientTesting(unittest.TestCase):

    def test_credential_hash_ok(self):
        client = Client('localhost', 'user', 'password', insecure=True)

        actual = client.credential_hash(hash_type=None)
        expected = '2b7cc318da9ba9d03912592c2f34a1ec'

        self.assertEqual(actual, expected)

        actual = client.credential_hash(hash_type='sha256')
        expected = '4234a9cea21fa911110cf36e96cd887049543ca31e7c95e04028290bde1db1e0'

        self.assertEqual(actual, expected)

    def test_credential_hash_error(self):
        client = Client('localhost', 'user', 'password', insecure=True)

        with self.assertRaises(Exception) as context:
            client.credential_hash(hash_type='foobar')

    def test_login_ok(self):
        client = Client('localhost', 'user', 'password', insecure=True)

        with open('test/fixtures/login.xml') as f:
            d = f.read()

        m = mock.MagicMock()
        m.request.return_value = MockRequest(200, d)

        client.session = m

        client.login('sha256')

        m.request.assert_called_with('GET', '/api/login/4234a9cea21fa911110cf36e96cd887049543ca31e7c95e04028290bde1db1e0', headers={})

    def test_login_error(self):
        client = Client('localhost', 'user', 'password', insecure=True)

        with open('test/fixtures/login-failed.xml') as f:
            d = f.read()

        m = mock.MagicMock()
        m.request.return_value = MockRequest(200, d)

        client.session = m

        with self.assertRaises(CriticalException) as context:
            client.login('sha256')

        m.request.assert_called_with('GET', '/api/login/4234a9cea21fa911110cf36e96cd887049543ca31e7c95e04028290bde1db1e0', headers={})

    def test_request_error(self):
        client = Client('localhost', 'user', 'password', insecure=True)

        m = mock.MagicMock()
        m.request.return_value = MockRequest(200, 'not XML')

        client.session = m

        with self.assertRaises(CriticalException) as context:
            client.get_component(Disks, "disks", "drives")

    @mock.patch('builtins.print')
    def test_request_ok(self, mock_print):
        client = Client('localhost', 'user', 'password', insecure=True)

        with open('test/fixtures/show-disks-small.xml') as f:
            d = f.read()

        m = mock.MagicMock()
        m.request.return_value = MockRequest(200, d)

        client.session = m
        mode = client.get_component(Disks, "disks", "drives")
        mode.print_and_return()

        mock_print.assert_called_with('[OK] 1 disks\n\n[1.1 ] SEAGATE ST10000NM002G 10.0TB SERIALNO Up OK\n| disk_1_1_temperature=26')
