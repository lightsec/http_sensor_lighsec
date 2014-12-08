'''
Created on 30/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
'''
import ConfigParser
from Crypto.Hash.SHA256 import SHA256Hash
from lightsec.helpers import SensorHelper
from lightsec.tools.key_derivation import KeyDerivationFunctionFactory, Nist800
from lightsec.tools.encryption import AESCTRCipher


kdf_factory = KeyDerivationFunctionFactory(Nist800, SHA256Hash(), 256)  # 512 )
sensor = SensorHelper(kdf_factory, SHA256Hash, AESCTRCipher)


class ConfigFileReader(object):
    
    def __init__(self, file_path):
        self.config = ConfigParser.RawConfigParser()
        self.config.read(file_path)

    def read_secrets_and_install(self, identifier):
        AUTH_KEY = self.config.get('Sensor', 'authkey')
        ENC_KEY = self.config.get('Sensor', 'enckey')
        sensor.install_secrets(AUTH_KEY, ENC_KEY)
    
    def configure_app_secret_key(self):
        from httplightsec.app import app
        app.secret_key = self.config.get('App', 'secret')