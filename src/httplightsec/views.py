"""
Created on 16/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
"""

from flask import redirect, request, render_template, url_for, jsonify
from httplightsec.app import app
from httplightsec.utils import login_required


SENSOR_ID = "sensor1"


@app.route("/")
def index():
    return "This is a sensor!"


def json_error(status, msg=None):
    message = {'status': status, 'message': msg}
    resp = jsonify(message)
    resp.status_code = status
    return resp


@app.errorhandler(400)
def incorrect_request(error=None):
    message = 'Incorrect request arguments.'
    if error is not None:
        message += "\n" + error.description
    return json_error(400, msg=message)


@app.errorhandler(401)
def not_authorized(error=None):
    message = 'Unauthorized content.'
    if error is not None:
        message += "\n" + error.description
    return json_error(401, msg=message)


@app.errorhandler(404)
def not_found(error=None):
    message = 'Not Found: %s.' % request.url
    if error is not None:
        message += "\n" + error.description
    return json_error(404, msg=message)


@app.route("/value")
@login_required(SENSOR_ID)
def show_value():
    return "Nice message."