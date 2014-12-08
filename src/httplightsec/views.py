'''
Created on 16/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>
'''

import binascii
from flask import redirect, request, session, render_template, url_for, jsonify
from lightsec.exceptions import UnauthorizedException, NoLongerAuthorizedException
from httplightsec.app import app
from httplightsec.auth import sensor


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


def json_error(status, error=None, msg=None):
    message = {'status': status, 'message': msg}
    resp = jsonify(message)
    resp.status_code = status
    return resp


@app.errorhandler(400)
def incorrect_request(error=None, msg=None):
    message = 'Incorrect request arguments.'
    if msg is not None:
        message += "\n" + msg
    return json_error(400, msg=message)


@app.errorhandler(401)
def not_authorized(error=None, msg=None):
    message = 'Unauthorized content.'
    if msg is not None:
        message += "\n" + msg
    return json_error(401, msg=message)


@app.errorhandler(404)
def not_found(error=None, msg=None):
    message = 'Not Found: %s.' % request.url
    if msg is not None:
        message += "\n" + msg
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


def get_response(id_user, msg):
    try:
        cipherresp = sensor.encrypt(id_user, msg)
        macresp = sensor.mac(msg, id_user)
        resp = {
            CIPHERED_RESPONSE_FIELD: binascii.hexlify(cipherresp),
            MAC_RESPONSE_FIELD: binascii.hexlify(macresp)
        }
        return jsonify(resp)
    except (UnauthorizedException, NoLongerAuthorizedException):
        return not_authorized()


@app.route("/value")
# @login_required # TODO something similar!
def show_value():
    # In http it make sense to receive an empty request,
    # so ENCRYPTED_ARG and MAC_ARG might not be sent by the client.

    # USERID must be sent either via argument or via cookies
    user_id = get_userid_and_store(request.args)
    if not user_id:
        return incorrect_request(msg="An argument named '%s' was expected." % USERID_ARG)

    if are_first_communication_args(request.args):
        # json_body = request.get_json(force=True) # force means that I always expect a json
        sensor.create_keys(user_id, request.args[A_ARG], float(request.args[INIT_TIME_ARG]),
                           float(request.args[EXP_TIME_ARG]), request.args[COUNTER_ARG],
                           identifier=user_id)
        # FIXME: not really needed as I expect nothing appart from the authentication info!
        # sensor.decrypt(id_user, ciphertext)
        # self.assertTrue( sensor.msg_is_authentic( deciphertext, mactext, id_user, stuff["a"], stuff["init_time"], user.initial_counter ) )

    return get_response(user_id, "Nice message.")