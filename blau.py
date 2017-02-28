#!/usr/bin/env python
#-*- coding: utf-8; -*-

import sys
import time
import json
import ldap
import bcrypt
import logging
import hashlib
import cx_Oracle
from datetime import datetime
from bldap import LdapUserData
from werkzeug.routing import BaseConverter
from functools import wraps, update_wrapper
from flask import Flask, jsonify, make_response, request, abort, Response
from flask_json import FlaskJSON, JsonError, json_response, as_json

class RegexConverter(BaseConverter):
    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]


app = Flask(__name__)
FlaskJSON(app)
app.config.from_pyfile('config.py')
app.url_map.converters['regex'] = RegexConverter

# VERSION, used by CEF log formatter
application_version = app.config['APPLICATION_VERSION']

global ldapuserdata
ldapuserdata = LdapUserData()


# Logging
logging.basicConfig(
    filename=app.config['LOG_FILE'],
    format=app.config['LOG_FORMAT'],
    level=logging.DEBUG
)


# basic authentication
def check_auth(username, password):
    return username == 'melf2stack' and password == 'melf2stack'

def authenticate():
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


# LOG ID mapping
# 100 = LDAP
# 200 = ORACLE
# 300  = JWT
# 900 = LOGIN - the user got the public key

def custom_log(log_type, log_id, log_message):
    logger = logging.getLogger("custom_log")

    client_ip = request.headers.get('X-Forwarded-For')
    user_ip = client_ip if client_ip else request.remote_addr

    extraLog = "CEF:0|Walmart|BLAU|%s|%s|%s|src=%s dvchost=%s requestClientApplication=%s requestMethod=%s requestPath=%s requestQueryString=%s message=%s" % \
        (application_version,
        log_id,
        log_type,
        user_ip,
        request.host,
        request.headers.get('User-Agent'),
        request.method,
        request.path,
        request.query_string,
        log_message)

    logger.info("%s" % extraLog)


def oracle_interface(user,action,jwt_hash=None):
    try:
        con = cx_Oracle.connect(app.config['DB_USER'], app.config['DB_PASS'], app.config['DB_HOST'] + '/' + app.config['DB_SERVICE_NAME'])

        if action == "select":
            cur = con.cursor()
            query = "SELECT USER_HASH FROM USER_HASH WHERE USER_ID = :id"
            cur.execute(query, id=user)
            jwt = cur.fetchall()
            cur.close()
            con.close()

            # if not exist
            if not jwt:
                return None
            else:
                return jwt

        if action == "update":
            cur = con.cursor()
            query = "UPDATE USER_HASH SET USER_HASH = :jwt_hash, MODIFIED_BY = :id, MODIFIED_DATE = sysdate WHERE USER_ID = :id"
            cur.execute(query, jwt_hash=jwt_hash, id=user)
            con.commit()
            cur.close()
            con.close()

            return True

        if action == "insert":
            cur = con.cursor()
            query = "INSERT INTO USER_HASH (USER_ID, USER_HASH, CREATED_BY, MODIFIED_BY, CREATED_DATE, MODIFIED_DATE, ACTIVE) values (:id, :jwt_hash, :id, :id, sysdate, sysdate, 1)"
            cur.execute(query, jwt_hash=jwt_hash, id=user)
            con.commit()
            cur.close()
            con.close()

            return True

        con.close()

    except cx_Oracle.DatabaseError as e:
        error, = e.args
        if error.code == 20000:
            logger.info("ORA: User %s does not exist" % user)
            return json_response(error="ORA: User %s does not exist" % user)
        else:
            logger.error("ORA: Unknown/unmapped error: %s" % error)
            return json_response(error="ORA: Unknown/unmapped error %s" % error)

def ldap_search(user, ldap_filter):

    # LDAP bind
    l = ldap.initialize(app.config['LDAP_HOST'])
    binddn = app.config['LDAP_BINDDN']
    pw = app.config['LDAP_PASS']
    basedn = app.config['LDAP_BASEDN']

    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    l.set_option(ldap.OPT_REFERRALS, 0)
    l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
    l.set_option(ldap.OPT_X_TLS,ldap.OPT_X_TLS_DEMAND)
    l.set_option(ldap.OPT_X_TLS_DEMAND, True )
    l.set_option(ldap.OPT_DEBUG_LEVEL, 255 )

    searchFilter = ldap_filter
    searchAttribute = ["sAMAccountName"]
    #this will scope the entire subtree under UserUnits
    searchScope = ldap.SCOPE_SUBTREE
    #Bind to the server
    try:
        l.protocol_version = ldap.VERSION3
        l.simple_bind_s(binddn, pw)
    except ldap.INVALID_CREDENTIALS:
        logger.error("LDAP: Your bind username or password is incorrect.")
        return json_response(error="LDAP: Your bind username or password is incorrect.")
        sys.exit(0)
    except ldap.LDAPError, e:
        if type(e.message) == dict and e.message.has_key('desc'):
            print e.message['desc']
        else:
            print e
            sys.exit(0)
    try:
        ldap_result_id = l.search(basedn, searchScope, searchFilter, searchAttribute)
        result_set = []
        while 1:
            result_type, result_data = l.result(ldap_result_id, 0)
            if (result_data == []):
                break
            else:
                ## if you are expecting multiple results you can append them
                ## otherwise you can just wait until the initial result and break out
                if result_type == ldap.RES_SEARCH_ENTRY:
                    result_set.append(result_data)
        return result_set
    except ldap.LDAPError, e:
        print e
    l.unbind_s()

def validate_account(user):
    logger = logging.getLogger("validateAccount")

    # check if the user exists
    account_exists = ldap_search(user, "(&(objectClass=user)(sAMAccountName=%s))" % user)
    if not account_exists:
        logger.info("LDAP: Account %s does not exist" % user)
        return "NotFound"

    # check whether user is locked or not
    account_is_locked = ldap_search(user, "(&(objectClass=user)(sAMAccountName=%s)(lockoutTime>=1))" % user)
    if account_is_locked:
        logger.info("LDAP: Account %s locked, unable to login" % user)
        return "Locked"

    # check whether user is disabled or not
    account_is_disabled = ldap_search(user, "(&(objectClass=user)(sAMAccountName=%s)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" % user)
    if not account_is_disabled:
        logger.info("LDAP: Account %s disabled, you should\'t be using this user, should you?" % user)
        return "Disabled"

    # check if user belongs to the br_gec_ssh group
    account_is_elegible = ldap_search(user, "(&(objectCategory=user)(objectClass=user)(sAMAccountName=%s)(memberOf=CN=%s,OU=Grupos,OU=WALMART,DC=vmcommerce,DC=intra)(memberOf=CN=%s,OU=Grupos,OU=WALMART,DC=vmcommerce,DC=intra))" % (user, app.config['LDAP_VALID_GROUP'][0], app.config['LDAP_VALID_GROUP'][1]))
    if not account_is_elegible:
        logger.info("LDAP: Account %s is not elegible" % user)
        return "NotElegible"

    return True


# send no-cache, security standards
def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers['Last-Modified'] = datetime.now()
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
        return response

    return update_wrapper(no_cache, view)

@app.route('/')
def index():
	return 'Hello World'

# ADD KEY, protect against injections...
@app.route('/v1/<regex("([-a-zA-Z0-9_]+)"):user>', methods=['POST'])
@requires_auth
@nocache
def setUser(user=None):
    logger = logging.getLogger("addKey")

    # Basic validation
    if user is None:
        abort(404)
    if not request.json:
        abort(400)
    data = json.loads(request.data)
    if not 'key' in data:
        abort(400)


    # validate if user is not locked or disabled
    account = validate_account(user)
    if account == "NotElegible":
        custom_log("100", "INFO", "LDAP: Account %s not elegible." % user)
        return json_response(200, status='error', message='LDAP: Account %s not elegible' % user)
    if account == "NotFound":
        custom_log("100", "INFO", "LDAP: Account %s not found." % user)
        return json_response(200, status="error", message='LDAP: Account %s not found' % user)
    if account == "Locked":
        custom_log("100", "INFO", "LDAP: Account %s locked, unable to login" % user)
        return json_response(200, status="error", message='LDAP: Account %s locked, unable to login' % user)
    if account == "Disabled":
        custom_log("100", "INFO", "LDAP: Account %s disabed" % user)
        return json_response(200, status="error", message='LDAP: Account %s disabed, you should\'t be using this user, should you?' % user)

    current_encrypted_data=oracle_interface(user,"select")
    pub_key=data['key']

    if current_encrypted_data:
        if bcrypt.check_used_key(user,pub_key,current_encrypted_data[0][0]):
            new_encrypted_data = bcrypt.update_data(
                app.config['PRIVATE_KEY_SECRET'],
                current_encrypted_data[0][0],
                pub_key,
                expire=app.config['KEY_TTL']
            )
            oracle_interface(user,"update",new_encrypted_data)
        else:
            custom_log("300", "INFO", "Key: Public key already used for user %s" % user)
            return json_response(200, status="error", message="Key: Public key already used for user %s" % user)
            return False
    else:
        new_encrypted_data = bcrypt.create_data(
            app.config['PRIVATE_KEY_SECRET'],
            user,
            pub_key,
            expire=app.config['KEY_TTL']
        )
        oracle_interface(user,"insert",new_encrypted_data)

    if new_encrypted_data:
        return json_response(200,
            id=user,
            ttl=app.config['KEY_TTL'],
            status='success',
            key_hash=new_encrypted_data,
            message='Key is valid for %s days' % str(app.config['KEY_TTL']))
    else:
        abort(500)



# GET KEY, protect against injections...
@app.route('/v1/<regex("([-a-zA-Z0-9_]+)"):user>', methods=['GET'])
@nocache
def getUser(user=None):
    logger = logging.getLogger("getUser")

    # get query_string format
    output_format = request.args.get('format')

    # validate if user is not locked or disabled
    account = validate_account(user)

    if account == "NotElegible":
        custom_log("100", "INFO", "LDAP: Account %s not elegible." % user)
        return json_response(200, status='error', message='LDAP: Account %s not elegible' % user)
    if account == "NotFound":
        custom_log("100", "INFO", "LDAP: Account %s not found." % user)
        return json_response(200, status='error', message='LDAP: Account %s not found' % user)
    if account == "Locked":
        custom_log("100", "INFO", "LDAP: Account %s locked, unable to login" % user)
        return json_response(200, status='error', message='LDAP: Account %s locked, unable to login' % user)
    if account == "Disabled":
        custom_log("100", "INFO", "LDAP: Account %s disabed" % user)
        return json_response(200, status='error', message='LDAP: Account %s disabed, you should\'t be using this user, should you?' % user)

    jwt_data = oracle_interface(user,"select")

    # if user does not exist on database
    if jwt_data is not None:
        jwt_content = bcrypt.validate_data(app.config['PRIVATE_KEY_SECRET'],jwt_data[0][0])
    else:
        custom_log("200", "INFO", "ORA: User not found on DB %s" % user)
        return json_response(200, status='error', message="ORA: User not fount on DB %s" % user)

    if not jwt_content:
        # jwt expired or invalid
        custom_log("300", "INFO", "JWT: Expired or invalid signature for user %s" % user)
        return json_response(200, status='error', message="JWT: Expired or invalid signature for user %s" % user)
    else:
        custom_log("900", "INFO", "Success on getting the public key for the user %s" % user)
        public_key = jwt_content['pub_key']
        public_key_ttl = time.strftime("%Y-%m-%d", time.localtime(int(jwt_content['exp'])))

        if output_format == "json":
            # return json format, used by melf2stack interface
            return json_response(200, status='success', message='keys is valid', key=public_key, ttl=public_key_ttl)
        else:
            # return raw format, used by our ssh agent servers
            return jwt_content['pub_key']



@app.route('/healthcheck')
@nocache
def healthcheck():
    logger = logging.getLogger("healthcheck")
    try:
        con = cx_Oracle.connect(app.config['DB_USER'], app.config['DB_PASS'], app.config['DB_HOST'] + '/' + app.config['DB_SERVICE_NAME'])
        if con.version:
            return "LIVE, Oracle version is: %s" % con.version
    except Exception, ex:
        logger.error("Cannot connect to ORACLE server: %s" % str(ex))
        return "DOWN, check oracle and/or ldap connection"

    cur.close()
    con.close()



# ERROR HANDLERS

@app.errorhandler(404)
def not_found(error):
    return make_response(
        jsonify({
        	'status': 'error',
        	'msg': 'Not found'
        }),
        404
    )

@app.errorhandler(400)
def bad_request(error):
    return make_response(
        jsonify({
            'status': 'error',
            'msg': 'Bad Request'
        }),
        404
    )

@app.errorhandler(500)
def error_request(error):
    return make_response(
        jsonify({
            'status': 'error',
            'msg': 'Internal Server Error'
        }),
        400
    )

if __name__ == "__main__":
    app.run()
