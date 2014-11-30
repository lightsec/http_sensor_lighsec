'''
Created on 16/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
'''

from flask import redirect, request, render_template, url_for, jsonify
from httplightsec.app import app
from httplightsec.auth import sensor


@app.route("/")
def index():
    return "This is a sensor!"

@app.errorhandler(404)
def not_found(error=None):
    message = {
            'status': 404,
            'message': 'Not Found: %s.\n%s' % (request.url, error),
    }
    resp = jsonify(message)
    resp.status_code = 404
    return resp


@app.route("/value")
#@login_required # TODO something similar!
def show_value():
    return "Logged!"