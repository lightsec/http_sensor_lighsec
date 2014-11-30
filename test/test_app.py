'''
Created on 30/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
'''
import os
import unittest
import tempfile
from httplightsec.app import app
from httplightsec.auth import *
from httplightsec.views import *


class FlaskrTestCase(unittest.TestCase):

    AUTH_KEY = "testkey1"
    ENC_KEY = "testkey2"

    def setUp(self):
        self.app = app.test_client()
        sensor.install_secrets(self.AUTH_KEY, self.ENC_KEY)

    #def tearDown(self):

    def test_empty_first_connection(self):
        rv = self.app.get('/value')
        assert 'Logged!' in rv.data


if __name__ == '__main__':
    unittest.main()