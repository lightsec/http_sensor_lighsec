"""
Created on 30/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
"""
import os
import unittest
import binascii
from flask.json import loads
from Crypto.Hash.SHA256 import SHA256Hash
from lightsec.helpers import BaseStationHelper, UserHelper
from lightsec.tools.key_derivation import KeyDerivationFunctionFactory, Nist800
from lightsec.tools.encryption import AESCTRCipher
from httplightsec.app import app
from httplightsec.auth import sensor
from httplightsec.views import *

app.secret_key = os.urandom(24)


class HttpSensorTestCase(unittest.TestCase):

    USER_ID = "user1"
    AUTH_KEY = "testkey1"
    ENC_KEY = "testkey2"

    def setUp(self):
        self.app = app.test_client()
        
        kdf_factory = KeyDerivationFunctionFactory(Nist800, SHA256Hash(), 256)  # 512 )
        self.base_station = BaseStationHelper(kdf_factory)
        self.base_station.install_secrets(SENSOR_ID, self.AUTH_KEY, self.ENC_KEY)
        stuff = self.base_station.create_keys(self.USER_ID, SENSOR_ID, 10)
        self.user = UserHelper(SENSOR_ID, stuff["kenc"], AESCTRCipher,
                               stuff["kauth"], SHA256Hash, self.USER_ID,
                               stuff["a"], stuff["init_time"], stuff["exp_time"])
        self.stuff = stuff
        
        sensor.install_secrets(self.AUTH_KEY, self.ENC_KEY, identifier=SENSOR_ID)

    # def tearDown(self):

    def test_root(self):
        rv = self.app.get('/')
        assert 'This is a sensor!' in rv.data

    def test_not_enough_info_for_the_first_communication(self):
        rv = self.app.get('/value', query_string={'hello': 'world'})
        assert rv.status == '400 BAD REQUEST'  # userid was not sent!
    
    def test_not_authorized(self):
        # the user is not logged yet
        rv = self.app.get('/value', query_string={USERID_ARG: self.USER_ID})
        assert rv.status == '401 UNAUTHORIZED'  # keying info not sent

    def _get_user_helper(self, user_id, stuff):
        return UserHelper(SENSOR_ID, stuff["kenc"], AESCTRCipher, stuff["kauth"],
                           SHA256Hash, user_id, stuff["a"], stuff["init_time"], stuff["exp_time"])

    def test_value_with_authorization(self):
        uh = self._get_user_helper(self.USER_ID, self.stuff)

        test_message = "holamundo"
        qs = {
            USERID_ARG: self.USER_ID,
            A_ARG: self.stuff['a'],
            INIT_TIME_ARG: self.stuff['init_time'],
            EXP_TIME_ARG: self.stuff['exp_time'],
            COUNTER_ARG: uh.initial_counter,
            ENCRYPTED_ARG: binascii.hexlify(uh.encrypt(test_message)),
            MAC_ARG: binascii.hexlify(uh.mac(test_message))
        }

        rv = self.app.get('/value', query_string=qs)

        # Checking that the response message has the expected format.
        assert rv.status == '200 OK'
        resp_obj = loads(rv.data)
        assert CIPHERED_RESPONSE_FIELD in resp_obj
        assert MAC_RESPONSE_FIELD in resp_obj

        # Check that the ciphered text is right:
        ciphered_resp_ba = binascii.unhexlify(resp_obj[CIPHERED_RESPONSE_FIELD])
        mac_resp_ba = binascii.unhexlify(resp_obj[MAC_RESPONSE_FIELD])

        # 1. Test that the user understands the sensor's response
        expected_response = "Nice message."
        deciphered_resp = uh.decrypt(ciphered_resp_ba)
        self.assertSequenceEqual(deciphered_resp, expected_response)

        # 2. Test that the user can validate the response received
        assert uh.msg_is_authentic(deciphered_resp, mac_resp_ba)

if __name__ == '__main__':
    unittest.main()