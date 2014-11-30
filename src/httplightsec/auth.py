'''
Created on 30/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
'''
import ConfigParser
from Crypto.Hash.SHA256 import SHA256Hash
from lightsec.helpers import SensorHelper
from lightsec.tools.key_derivation import KeyDerivationFunctionFactory, Nist800
from lightsec.tools.encryption import AESCTRCipher


config = ConfigParser.RawConfigParser()
config.read("../../config.ini")
AUTH_KEY = config.get('Sensor', 'authkey')
ENC_KEY = config.get('Sensor', 'enckey')


kdf_factory = KeyDerivationFunctionFactory( Nist800, SHA256Hash(), 256 ) # 512 ) 
sensor = SensorHelper( kdf_factory, SHA256Hash, AESCTRCipher )
sensor.install_secrets(AUTH_KEY, ENC_KEY)