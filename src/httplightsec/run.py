'''
Created on 30/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
'''

from httplightsec.app import app
from httplightsec.auth import *
from httplightsec.views import *


if __name__ == "__main__":
    app.run()