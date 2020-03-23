from app import app, iam_blueprint
from flask import redirect, render_template, session, url_for, json
from functools import wraps
import ast
import requests
from . import utils, settings


def validate_configuration():
    if not settings.orchestratorConf.get('im_url'):
        app.logger.debug("Trying to (re)load config from Orchestrator: " + json.dumps(settings.orchestratorConf))
        access_token = iam_blueprint.session.token['access_token']
        configuration = utils.getorchestratorconfiguration(settings.orchestratorUrl, access_token)
        settings.orchestratorConf = configuration


def authorized_with_valid_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):

        if not iam_blueprint.session.authorized or 'username' not in session:
            return redirect(url_for('login'))

        if iam_blueprint.session.token['expires_in'] < 60:
            app.logger.debug("Force refresh token")
            iam_blueprint.session.get('/userinfo')

        validate_configuration()

        return f(*args, **kwargs)

    return decorated_function


def only_for_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session['userrole'].lower() == 'admin':
            return render_template(app.config.get('HOME_TEMPLATE'))

        return f(*args, **kwargs)

    return decorated_function


def exchange_token_with_audience(iam_url, client_id, client_secret, iam_token, audience):

    payload_string = '{ "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "audience": "' \
                     + audience + '", "subject_token": "' + iam_token + '", "scope": "openid profile" }'

    # Convert string payload to dictionary
    payload = ast.literal_eval(payload_string)

    iam_response = requests.post(iam_url + "/token", data=payload, auth=(client_id, client_secret), verify=False)

    if not iam_response.ok:
        raise Exception("Error exchanging token: {} - {}".format(iam_response.status_code, iam_response.text))

    deserialized_iam_response = json.loads(iam_response.text)

    return deserialized_iam_response['access_token']
