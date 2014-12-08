'''
Created on 16/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
'''

import binascii
from flask import abort, redirect, request, session, render_template, url_for, jsonify
from lightsec.exceptions import UnauthorizedException, NoLongerAuthorizedException
from httplightsec.app import app
from httplightsec.auth import sensor


SENSOR_ID = "sensor1"
USERID_ARG = 'userid'
ENCRYPTED_ARG = 'encryptedMsg'
A_ARG = 'a'
INIT_TIME_ARG = 'init'
EXP_TIME_ARG = 'expiration'
COUNTER_ARG = 'ctr'
MAC_ARG = 'mac'
CIPHERED_RESPONSE_FIELD = 'ciphered'
MAC_RESPONSE_FIELD = 'mac'


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


def get_userid_and_store(args):
    """
    Gets the userid either from args or the session information (cookies).

    When it is taken from the args, it also stores it in the session.
    """
    userid = args.get(USERID_ARG)
    if userid:
        session[USERID_ARG] = userid
        return userid
    if USERID_ARG in session:
        return session[USERID_ARG]
    return None  # better explicit


def are_first_communication_args(args):
    """
    From the doc:
    'A encrypts her first message to S with KencS,A in counter mode
    (thus using a fresh counter ctr), attaches parameters IDA ,
    a, init time, exp time, ctr in plain text and a MAC obtained
    with KauthS,A.'
    """
    expected_args = (ENCRYPTED_ARG, A_ARG, INIT_TIME_ARG,
                     EXP_TIME_ARG, COUNTER_ARG, MAC_ARG)
    got_args = args.keys()
    for expected_arg in expected_args:
        if expected_arg not in got_args:
            return False
    return True


def encrypt_message(id_user, unencrypted_message):
    try:
        cipherresp = sensor.encrypt(id_user, unencrypted_message)
        macresp = sensor.mac(unencrypted_message, id_user)
        resp = {
            CIPHERED_RESPONSE_FIELD: binascii.hexlify(cipherresp),
            MAC_RESPONSE_FIELD: binascii.hexlify(macresp)
        }
        return jsonify(resp)
    except (UnauthorizedException, NoLongerAuthorizedException):
        abort(401)


def login_required(f):
    def wrapped(*args, **kwargs):
        # USERID must be sent either via argument or via cookies
        user_id = get_userid_and_store(request.args)
        if not user_id:
            abort(400, description="An argument named '%s' was expected." % USERID_ARG)

        if are_first_communication_args(request.args):
            # json_body = request.get_json(force=True) # force means that I always expect a json
            sensor.create_keys(user_id, request.args[A_ARG], float(request.args[INIT_TIME_ARG]),
                               float(request.args[EXP_TIME_ARG]), request.args[COUNTER_ARG],
                               identifier=SENSOR_ID)

        # In http it makes sense to receive an empty request,
        # so ENCRYPTED_ARG and MAC_ARG might not be sent by the client.
        # However, our algorithm expects this so the counter used in the ciphering increases.
        enc_ba = binascii.unhexlify(request.args[ENCRYPTED_ARG])
        mac_ba = binascii.unhexlify(request.args[MAC_ARG])
        try:
            decoded_msg = sensor.decrypt(user_id, enc_ba)  # We just use it to check the mac
            if not sensor.msg_is_authentic(decoded_msg, mac_ba, user_id, request.args[A_ARG], request.args[INIT_TIME_ARG],
                                           request.args[COUNTER_ARG]):
                abort(401)
        except (UnauthorizedException, NoLongerAuthorizedException):
            abort(401)

        # call to the original function
        unencrypted_msg = f(*args, **kwargs)
        return encrypt_message(user_id, unencrypted_msg)
    wrapped.__name__ = f.__name__
    wrapped.__doc__  = f.__doc__
    return wrapped

@app.route("/value")
@login_required
def show_value():
    return "Nice message."