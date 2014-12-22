"""
Created on 30/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
"""

from argparse import ArgumentParser
from httplightsec.app import app
from httplightsec.auth import *
from httplightsec.views import *


def main():
    parser = ArgumentParser(description='Run sample web server which uses liblightsec.')
    parser.add_argument('-config', default='../../config.ini', dest='config',
                        help='Configuration file.')
    args = parser.parse_args()

    cfr = ConfigFileReader(args.config)
    cfr.configure_app_secret_key()
    cfr.read_secrets_and_install()

    app.run(host='0.0.0.0')

if __name__ == "__main__":
    main()