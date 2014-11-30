'''
Created on 30/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
'''
import os
import unittest
import tempfile
from Crypto.Hash.SHA256 import SHA256Hash
from lightsec.helpers import BaseStationHelper, SensorHelper, UserHelper
from lightsec.tools.key_derivation import KeyDerivationFunctionFactory, Nist800
from lightsec.tools.encryption import AESCTRCipher
from httplightsec.app import app
from httplightsec.auth import sensor
from httplightsec.views import *

app.secret_key = os.urandom(24)

class HttpSensorTestCase(unittest.TestCase):

    USER_ID = "user1"
    SENSOR_ID = "sensor1"
    AUTH_KEY = "testkey1"
    ENC_KEY = "testkey2"

    def setUp(self):
        self.app = app.test_client()
        
        kdf_factory = KeyDerivationFunctionFactory( Nist800, SHA256Hash(), 256 ) # 512 ) 
        self.base_station = BaseStationHelper(kdf_factory)
        self.base_station.install_secrets(self.SENSOR_ID, self.AUTH_KEY,
                                          self.ENC_KEY)
        stuff = self.base_station.create_keys(self.USER_ID, self.SENSOR_ID, 10)
        self.user = UserHelper(self.SENSOR_ID, stuff["kenc"], AESCTRCipher,
                               stuff["kauth"], SHA256Hash, self.USER_ID,
                               stuff["a"], stuff["init_time"], stuff["exp_time"] )
        self.stuff = stuff
        
        sensor.install_secrets(self.AUTH_KEY, self.ENC_KEY, identifier=self.USER_ID)

    #def tearDown(self):

    def test_root(self):
        rv = self.app.get('/')
        assert 'This is a sensor!' in rv.data

    def test_not_enough_info_for_the_first_communication(self):
        rv = self.app.get('/value', query_string={'hello': 'world'})
        assert rv.status=='400 BAD REQUEST' # userid was not sent!
    
    def test_not_authorized(self):
        # the user is not logged yet
        rv = self.app.get('/value', query_string={USERID_ARG: self.USER_ID})
        assert rv.status=='401 UNAUTHORIZED' # userid was not sent!


if __name__ == '__main__':
    unittest.main()