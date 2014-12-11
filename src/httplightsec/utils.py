"""
Created on 16/11/2014

@author: Aitor Gomez Goiri <aitor.gomez@deusto.es>

'login_required' decorator and its auxiliary functions.
"""

import binascii
from flask import abort, request, session, jsonify
from lightsec.exceptions import UnauthorizedException, NoLongerAuthorizedException
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
    expected_args = (A_ARG, INIT_TIME_ARG,
                     EXP_TIME_ARG, COUNTER_ARG)
    got_args = args.keys()
    for expected_arg in expected_args:
        if expected_arg not in got_args:
            return False
    return True


def encrypt_message(id_user, unencrypted_message):
    cipherresp = sensor.encrypt(id_user, unencrypted_message)
    macresp = sensor.mac(unencrypted_message, id_user)
    resp = {
        CIPHERED_RESPONSE_FIELD: binascii.hexlify(cipherresp),
        MAC_RESPONSE_FIELD: binascii.hexlify(macresp)
    }
    return jsonify(resp)


def login_required(key_identifier="default"):
    def wrap(f):  # see http://www.artima.com/weblogs/viewpost.jsp?thread=240845
        def wrapped(*args, **kwargs):
            # USERID must be sent either via argument or via cookies
            user_id = get_userid_and_store(request.args)
            if not user_id:
                abort(400, description="An argument named '%s' was expected." % USERID_ARG)

            a_arg = None
            init_time_arg = None
            counter_arg = None
            if are_first_communication_args(request.args):
                a_arg = request.args[A_ARG]
                init_time_arg = request.args[INIT_TIME_ARG]
                counter_arg = request.args[COUNTER_ARG]
                sensor.create_keys(user_id, a_arg, float(init_time_arg), float(request.args[EXP_TIME_ARG]),
                                   counter_arg, identifier=key_identifier)

            # In http it makes sense to receive an empty request,
            # so ENCRYPTED_ARG and MAC_ARG might not be sent by the client.
            # However, our algorithm expects this so the counter used in the ciphering increases.
            try:
                if ENCRYPTED_ARG in request.args:
                    enc_ba = binascii.unhexlify(request.args[ENCRYPTED_ARG])
                    decoded_msg = sensor.decrypt(user_id, enc_ba)  # We just use it to check the mac

                    if MAC_ARG in request.args:
                        mac_ba = binascii.unhexlify(request.args[MAC_ARG])
                        if not sensor.msg_is_authentic(decoded_msg, mac_ba, user_id, a_arg, init_time_arg, counter_arg):
                            abort(401)

                # call to the original function
                unencrypted_msg = f(*args, **kwargs)
                return encrypt_message(user_id, unencrypted_msg)
            except (UnauthorizedException, NoLongerAuthorizedException):
                abort(401)

        wrapped.__name__ = f.__name__
        wrapped.__doc__  = f.__doc__
        return wrapped
    return wrap
