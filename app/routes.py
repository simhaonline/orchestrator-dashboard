from app import app, iam_blueprint, sla as sla, mail, settings, utils
from markupsafe import Markup
from app import db
from app.models import Deployment, User
from werkzeug.exceptions import Forbidden
from flask import json, render_template, request, redirect, url_for, flash, session, make_response
from flask_mail import Message
import requests
import json
import datetime
import yaml
import io
import linecache
import sys
import base64
import struct
import binascii
from functools import wraps
from packaging import version
from dateutil import parser
import uuid as uuid_generator

# Hashicorp vault support integration
from app.vault_integration import VaultIntegration

iam_base_url = settings.iamUrl
iam_client_id = settings.iamClientID
iam_client_secret = settings.iamClientSecret

issuer = settings.iamUrl
if not issuer.endswith('/'):
    issuer += '/'

app.jinja_env.filters['tojson_pretty'] = utils.to_pretty_json

toscaTemplates = utils.loadtoscatemplates(settings.toscaDir)
toscaInfo = utils.extracttoscainfo(settings.toscaDir,
                                   settings.toscaParamsDir,
                                   toscaTemplates,
                                   settings.toscaMetadataDir)

app.logger.debug("TOSCA INFO: " + json.dumps(toscaInfo))
app.logger.debug("EXTERNAL_LINKS: " + json.dumps(settings.external_links))
app.logger.debug("ENABLE_ADVANCED_MENU: " + str(settings.enable_advanced_menu))

# ______________________________________
# TODO move from here
# vault section
vault_url = app.config.get('VAULT_URL')
if vault_url:
    app.config.from_json('vault-config.json')
    vault_secrets_path = app.config.get('VAULT_SECRETS_PATH')
    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_wrapping_token_time_duration = app.config.get("WRAPPING_TOKEN_TIME_DURATION")
    vault_read_policy = app.config.get("READ_POLICY")
    vault_read_token_time_duration = app.config.get("READ_TOKEN_TIME_DURATION")
    vault_read_token_renewal_duration = app.config.get("READ_TOKEN_RENEWAL_TIME_DURATION")
    vault_write_policy = app.config.get("WRITE_POLICY")
    vault_write_token_time_duration = app.config.get("WRITE_TOKEN_TIME_DURATION")
    vault_wtite_token_renewal_time_duration = app.config.get("WRITE_TOKEN_RENEWAL_TIME_DURATION")
    vault_delete_policy = app.config.get("DELETE_POLICY")
    vault_delete_token_time_duration = app.config.get("DELETE_TOKEN_TIME_DURATION")
    vault_delete_token_renewal_time_duration = app.config.get("DELETE_TOKEN_RENEWAL_TIME_DURATION")


@app.before_request
def before_request_checks():
    if 'external_links' not in session:
        session['external_links'] = settings.external_links
    if 'enable_advanced_menu' not in session:
        session['enable_advanced_menu'] = settings.enable_advanced_menu


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
            return render_template('home.html')

        return f(*args, **kwargs)

    return decorated_function


@app.route('/settings')
@authorized_with_valid_token
def show_settings():
    return render_template('settings.html',
                           iam_url=settings.iamUrl,
                           orchestrator_url=settings.orchestratorUrl,
                           orchestrator_conf=settings.orchestratorConf,
                           vault_url=vault_url)


@app.route('/deployments/<subject>')
@authorized_with_valid_token
@only_for_admin
def show_deployments(subject):
    #  if not session['userrole'].lower() == 'admin':
    #    return render_template('home.html')

    user = get_user(subject)

    if user is not None:
        #
        # retrieve deployments from orchestrator
        access_token = iam_blueprint.session.token['access_token']

        headers = {'Authorization': 'bearer %s' % access_token}

        url = settings.orchestratorUrl + "/deployments?createdBy={}&page={}&size={}".format(
            '{}@{}'.format(subject, issuer), 0, 999999)
        response = requests.get(url, headers=headers)

        deporch = []
        if response.ok:
            deporch = response.json()["content"]
            deporch = updatedeploymentsstatus(deporch, subject)

        iids = []
        # make map of remote deployments
        for dj in deporch:
            iids.append(dj.uuid)

        #
        # retrieve deployments from DB
        # deployments = Deployment.query.filter_by(sub=user.sub).all()
        deployments = cvdeployments(Deployment.query.filter_by(sub=user.sub).all())
        for dep in deployments:
            newremote = dep.remote
            if dep.uuid not in iids:
                if dep.remote == 1:
                    newremote = 0
            else:
                if dep.remote == 0:
                    newremote = 1
            if dep.remote != newremote:
                Deployment.query.filter_by(uuid=dep.uuid).update(dict(remote=newremote))
                db.session.commit()

        return render_template('dep_user.html', user=user, deployments=deployments)
    else:
        flash("User not found!")
        users = get_users()
        return render_template('users.html', users=users)


@app.route('/user/<subject>', methods=['GET', 'POST'])
@authorized_with_valid_token
@only_for_admin
def show_user(subject):
    #  if not session['userrole'].lower() == 'admin':
    #    return render_template('home.html')

    if request.method == 'POST':

        # cannot change its own role
        if session['userid'] == subject:
            role = session['userrole']
        else:
            role = request.form['role']
        active = request.form['active']
        # update database
        User.query.filter_by(sub=subject).update(dict(role=role, active=active))
        db.session.commit()

    user = get_user(subject)
    if user is not None:
        return render_template('user.html', user=user)
    else:
        return render_template('home.html')


def get_users():
    users = User.query.order_by(User.family_name.desc(), User.given_name.desc()).all()
    return users


def get_user(subject):
    user = User.query.get(subject)
    return user


def get_deployment(uuid):
    deployment = Deployment.query.get(uuid)
    return deployment


@app.route('/users')
@authorized_with_valid_token
@only_for_admin
def show_users():
    # if not session['userrole'].lower() == 'admin':
    #    return render_template('home.html')

    users = get_users()

    return render_template('users.html', users=users)


@app.route('/login')
def login():
    session.clear()
    return render_template('home.html')


@app.route('/slas')
@authorized_with_valid_token
def getslas():
    slas = {}

    try:
        access_token = iam_blueprint.session.token['access_token']
        slas = sla.get_slas(access_token, settings.orchestratorConf['slam_url'], settings.orchestratorConf['cmdb_url'])
        app.logger.debug("SLAs: {}".format(slas))

    except Exception as e:
        flash("Error retrieving SLAs list: \n" + str(e), 'warning')

    return render_template('sla.html', slas=slas)


def cvdeployments(deps):
    deployments = []
    for d in deps:
        deployments.append(cvdeployment(d))
    return deployments


def cvdeployment(d):
    deployment = Deployment(uuid=d.uuid,
                            creation_time=d.creation_time,
                            update_time=d.update_time,
                            physicalId='' if d.physicalId is None else d.physicalId,
                            description=d.description,
                            status=d.status,
                            status_reason=d.status_reason,
                            outputs=json.loads(d.outputs.replace("\n",
                                                                 "\\n")) if (d.outputs is not None
                                                                             and d.outputs is not '') else '',
                            task=d.task,
                            links=json.loads(
                                d.links.replace("\n", "\\n")) if (d.links is not None and d.links is not '') else '',
                            sub=d.sub,
                            template=d.template,
                            inputs=json.loads(
                                d.inputs.replace("\n", "\\n")) if (d.inputs is not None and d.inputs is not '') else '',
                            params=d.params,
                            provider_name='' if d.provider_name is None else d.provider_name,
                            endpoint=d.endpoint,
                            remote=d.remote,
                            locked=d.locked,
                            issuer=d.issuer,
                            feedback_required=d.feedback_required,
                            storage_encryption=d.storage_encryption,
                            vault_secret_uuid='' if d.vault_secret_uuid is None else d.vault_secret_uuid,
                            vault_secret_key='' if d.vault_secret_key is None else d.vault_secret_key,
                            elastic=d.elastic,
                            upgradable=d.upgradable)
    return deployment


def updatedeploymentsstatus(deployments, userid):
    deps = []
    iids = []
    # uuid = ''

    # update deployments status in database
    for dep_json in deployments:
        uuid = dep_json['uuid']
        iids.append(uuid)

        # sanitize date
        dt = parser.parse(dep_json['creationTime'])
        dep_json['creationTime'] = dt.strftime("%Y-%m-%d %H:%M:%S")
        dt = parser.parse(dep_json['updateTime'])
        dep_json['updateTime'] = dt.strftime("%Y-%m-%d %H:%M:%S")

        providername = dep_json['cloudProviderName'] if 'cloudProviderName' in dep_json else ''
        status_reason = dep_json['statusReason'] if 'statusReason' in dep_json else ''
        vphid = dep_json['physicalId'] if 'physicalId' in dep_json else ''

        dep = get_deployment(uuid)

        if dep is not None:
            if dep.status != dep_json['status'] or dep.provider_name != providername \
                    or dep.status_reason != status_reason:
                dep.update_time = dep_json['updateTime']
                dep.physicalId = vphid
                dep.status = dep_json['status']
                dep.outputs = json.dumps(dep_json['outputs'])
                dep.task = dep_json['task']
                dep.links = json.dumps(dep_json['links'])
                dep.remote = 1
                dep.provider_name = providername
                dep.status_reason = status_reason

                db.session.add(dep)
                db.session.commit()

            deps.append(dep)
        else:
            app.logger.info("Deployment with uuid:{} not found!".format(uuid))

            # retrieve template
            access_token = iam_blueprint.session.token['access_token']
            headers = {'Authorization': 'bearer %s' % access_token}

            url = settings.orchestratorUrl + "/deployments/" + uuid + "/template"
            response = requests.get(url, headers=headers)

            template = '' if not response.ok else response.text

            # insert missing deployment in database
            endpoint = dep_json['outputs']['endpoint'] if 'endpoint' in dep_json['outputs'] else ''

            deployment = Deployment(uuid=uuid,
                                    creation_time=dep_json['creationTime'],
                                    update_time=dep_json['updateTime'],
                                    physicalId=vphid,
                                    description='',
                                    status=dep_json['status'],
                                    outputs=json.dumps(dep_json['outputs']),
                                    task=dep_json['task'],
                                    links=json.dumps(dep_json['links']),
                                    sub=userid,
                                    template=template,
                                    inputs='',
                                    params='',
                                    provider_name=providername,
                                    endpoint=endpoint,
                                    remote=1,
                                    locked=0,
                                    issuer=dep_json['createdBy']['issuer'],
                                    storage_encryption=0,
                                    vault_secret_uuid='',
                                    vault_secret_key='',
                                    elastic=0,
                                    upgradable=0)

            db.session.add(deployment)
            db.session.commit()

            deps.append(deployment)

    # check delete in progress or missing
    dd = Deployment.query.filter(Deployment.sub == userid, Deployment.status == 'DELETE_IN_PROGRESS').all()

    for d in dd:
        uuid = d.uuid
        if uuid not in iids:
            time_string = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            d.status = 'DELETE_COMPLETE'
            d.update_time = time_string
            db.session.add(d)
            db.session.commit()

    return deps


def logexception(err):
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    app.logger.error('{} at ({}, LINE {} "{}"): {}'.format(err, filename, lineno, line.strip(), exc_obj))


@app.route('/')
def home():
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    account_info = iam_blueprint.session.get("/userinfo")

    if account_info.ok:
        account_info_json = account_info.json()

        if settings.iamGroups:
            user_groups = account_info_json['groups']
            if not set(settings.iamGroups).issubset(user_groups):
                app.logger.debug("No match on group membership. User group membership: " + json.dumps(user_groups))
                message = Markup(
                    'You need to be a member of the following IAM groups: {0}. <br>' +
                    'Please, visit <a href="{1}">{1}</a> and apply for the requested membership.'.format(
                        json.dumps(settings.iamGroups), settings.iamUrl))
                raise Forbidden(description=message)

        session['userid'] = account_info_json['sub']
        session['username'] = account_info_json['name']
        session['useremail'] = account_info_json['email']
        session['userrole'] = 'user'
        session['gravatar'] = utils.avatar(account_info_json['email'], 26)
        session['organisation_name'] = account_info_json['organisation_name']
        # access_token = iam_blueprint.session.token['access_token']

        # check database
        # if user not found, insert
        #
        user = get_user(account_info_json['sub'])
        if user is None:
            email = account_info_json['email']
            admins = json.dumps(app.config['ADMINS'])
            role = 'admin' if email in admins else 'user'

            user = User(sub=account_info_json['sub'],
                        name=account_info_json['name'],
                        username=account_info_json['preferred_username'],
                        given_name=account_info_json['given_name'],
                        family_name=account_info_json['family_name'],
                        email=email,
                        organisation_name=account_info_json['organisation_name'],
                        picture=utils.avatar(email, 26),
                        role=role,
                        active=1)
            db.session.add(user)
            db.session.commit()

        session['userrole'] = user.role  # role

        return render_template('portfolio.html', templates=toscaInfo)


@app.route('/deployments')
@authorized_with_valid_token
def showdeployments():
    access_token = iam_blueprint.session.token['access_token']

    headers = {'Authorization': 'bearer %s' % access_token}

    url = settings.orchestratorUrl + "/deployments?createdBy=me&page={}&size={}".format(0, 999999)
    response = requests.get(url, headers=headers)

    deployments = {}
    if not response.ok:
        flash("Error retrieving deployment list: \n" + response.text, 'warning')
    else:
        deployments = response.json()["content"]
        deployments = updatedeploymentsstatus(deployments, session['userid'])
        app.logger.debug("Deployments: " + str(deployments))

        deployments_uuid_array = []
        for deployment in deployments:
            deployments_uuid_array.append(deployment.uuid)
        session['deployments_uuid_array'] = deployments_uuid_array

    return render_template('deployments.html', deployments=deployments)


@app.route('/template/<depid>')
@authorized_with_valid_token
def deptemplate(depid=None):
    access_token = iam_blueprint.session.token['access_token']
    headers = {'Authorization': 'bearer %s' % access_token}

    url = settings.orchestratorUrl + "/deployments/" + depid + "/template"
    response = requests.get(url, headers=headers)

    if not response.ok:
        flash("Error getting template: " + response.text)
        return redirect(url_for('home'))

    template = response.text
    return render_template('deptemplate.html', template=template)


@app.route('/lockdeployment/<depid>')
@authorized_with_valid_token
def lockdeployment(depid=None):
    dep = get_deployment(depid)
    if dep is not None:
        dep.locked = 1
        db.session.add(dep)
        db.session.commit()
    return redirect(url_for('showdeployments'))


@app.route('/unlockdeployment/<depid>')
@authorized_with_valid_token
def unlockdeployment(depid=None):
    dep = get_deployment(depid)
    if dep is not None:
        dep.locked = 0
        db.session.add(dep)
        db.session.commit()
    return redirect(url_for('showdeployments'))


@app.route('/output/<depid>')
@authorized_with_valid_token
def depoutput(depid=None):
    if not session['userrole'].lower() == 'admin' and depid not in session['deployments_uuid_array']:
        flash("You are not allowed to browse this page!")
        return redirect(url_for('showdeployments'))

    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep is None:
        return redirect(url_for('home'))
    else:

        inputs = json.loads(dep.inputs.strip('\"')) if dep.inputs else {}
        outputs = json.loads(dep.outputs.strip('\"')) if dep.outputs else {}

        return render_template('depoutput.html',
                               deployment=dep,
                               inputs=inputs,
                               outputs=outputs)


@app.route('/templatedb/<depid>')
def deptemplatedb(depid):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep is None:
        return redirect(url_for('home'))
    else:
        template = dep.template
        return render_template('deptemplate.html', template=template)


@app.route('/log/<physicalId>')
@authorized_with_valid_token
def deplog(physicalId=None):
    access_token = iam_blueprint.session.token['access_token']
    headers = {'Authorization': 'id = im; type = InfrastructureManager; token = %s;' % access_token}

    app.logger.debug("Configuration: " + json.dumps(settings.orchestratorConf))

    url = settings.orchestratorConf['im_url'] + "/infrastructures/" + physicalId + "/contmsg"
    response = requests.get(url, headers=headers)

    log = "Not found" if not response.ok else response.text
    return render_template('deplog.html', log=log)


@app.route('/delete/<depid>')
@authorized_with_valid_token
def depdel(depid=None):
    access_token = iam_blueprint.session.token['access_token']
    headers = {'Authorization': 'bearer %s' % access_token}
    url = settings.orchestratorUrl + "/deployments/" + depid
    response = requests.delete(url, headers=headers)

    if not response.ok:
        flash("Error deleting deployment: " + response.text)
    else:
        dep = get_deployment(depid)
        if dep is not None and dep.storage_encryption == 1:
            secret_path = session['userid'] + "/" + dep.vault_secret_uuid
            delete_secret_from_vault(access_token, secret_path)

    return redirect(url_for('showdeployments'))


def delete_secret_from_vault(access_token, secret_path):
    vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience,
                             access_token, vault_secrets_path)

    auth_token = vault.get_auth_token()

    delete_token = vault.get_token(auth_token, vault_delete_policy, vault_delete_token_time_duration,
                                   vault_delete_token_renewal_time_duration)

    vault.delete_secret(delete_token, secret_path)


@app.route('/configure')
@authorized_with_valid_token
def configure():
    access_token = iam_blueprint.session.token['access_token']

    selected_tosca = request.args['selected_tosca']

    template = toscaInfo[selected_tosca]
    sla_id = utils.getslapolicy(template)

    slas = sla.get_slas(access_token, settings.orchestratorConf['slam_url'], settings.orchestratorConf['cmdb_url'], template["deployment_type"])

    ssh_pub_key = get_ssh_pub_key()

    return render_template('createdep.html',
                           template=template,
                           selectedTemplate=selected_tosca,
                           ssh_pub_key=ssh_pub_key,
                           slas=slas,
                           sla_id=sla_id)


def remove_sla_from_template(template):
    if 'policies' in template['topology_template']:
        for policy in template['topology_template']['policies']:
            for (k, v) in policy.items():
                if "type" in v \
                        and (
                        v['type'] == "tosca.policies.indigo.SlaPlacement" or v['type'] == "tosca.policies.Placement"):
                    template['topology_template']['policies'].remove(policy)
                    break
        if len(template['topology_template']['policies']) == 0:
            template['topology_template'].remove('policies')


def add_sla_to_template(template, sla_id):
    # Add or replace the placement policy

    if version.parse(utils.getorchestratoroersion(settings.orchestratorUrl)) >= version.parse("2.2.0-SNAPSHOT"):
        tosca_sla_placement_type = "tosca.policies.indigo.SlaPlacement"
    else:
        tosca_sla_placement_type = "tosca.policies.Placement"

    template['topology_template']['policies'] = [
        {"deploy_on_specific_site": {"type": tosca_sla_placement_type, "properties": {"sla_id": sla_id}}}]

    app.logger.debug(yaml.dump(template, default_flow_style=False))

    return template


@app.route('/submit', methods=['POST'])
@authorized_with_valid_token
def createdep():
    access_token = iam_blueprint.session.token['access_token']
    callback_url = app.config['CALLBACK_URL']

    app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

    with io.open(settings.toscaDir + request.args.get('template')) as stream:
        template = yaml.full_load(stream)
        # rewind file
        stream.seek(0)
        template_text = stream.read()

        form_data = request.form.to_dict()

        params = {}

        params['keepLastAttempt'] = 'true' if 'extra_opts.keepLastAttempt' in form_data else 'false'

        if 'extra_opts.providerTimeoutSet' in form_data:
            params['providerTimeoutMins'] = form_data['extra_opts.providerTimeout']

        params['timeoutMins'] = app.config['OVERALL_TIMEOUT']

        if form_data['extra_opts.schedtype'].lower() == "man":
            template = add_sla_to_template(template, form_data['extra_opts.selectedSLA'])
        else:
            remove_sla_from_template(template)

        feedback_required = 1 if 'extra_opts.sendEmailFeedback' in form_data else 0    
        params['callback'] = callback_url #always needed

        additionaldescription = form_data['additional_description']

        inputs = {k: v for (k, v) in form_data.items() if not k.startswith("extra_opts.")}

        storage_encryption = 0
        vault_secret_uuid = ''
        vault_secret_key = ''
        if 'storage_encryption' in inputs and inputs['storage_encryption'].lower() == 'true':
            storage_encryption = 1
            vault_secret_key = 'secret'

        if storage_encryption == 1:
            inputs['vault_url'] = vault_url
            vault_secret_uuid = str(uuid_generator.uuid4())
            if 'vault_secret_key' in inputs:
                vault_secret_key = inputs['vault_secret_key']
            app.logger.debug("Storage encryption enabled, appending wrapping token.")
            inputs['vault_wrapping_token'] = create_vault_wrapping_token(access_token)
            inputs['vault_secret_path'] = session['userid'] + '/' + vault_secret_uuid

        if 'instance_key_pub' in inputs and inputs['instance_key_pub'] == '':
            inputs['instance_key_pub'] = get_ssh_pub_key()

        app.logger.debug("Parameters: " + json.dumps(inputs))

        payload = {"template": yaml.dump(template, default_flow_style=False, sort_keys=False),
                   "parameters": inputs}\
                   .update(params)

        elastic = utils.eleasticdeployment(template)
        upgradable = utils.upgradabledeployment(template)

    url = settings.orchestratorUrl + "/deployments/"
    headers = {'Content-Type': 'application/json', 'Authorization': 'bearer %s' % access_token}
    response = requests.post(url, json=payload, params=params, headers=headers)

    if not response.ok:
        flash("Error submitting deployment: \n" + response.text)
    else:
        # store data into database
        rs_json = json.loads(response.text)
        uuid = rs_json['uuid']
        deployment = get_deployment(uuid)
        if deployment is None:

            vphid = rs_json['physicalId'] if 'physicalId' in rs_json else ''
            providername = rs_json['cloudProviderName'] if 'cloudProviderName' in rs_json else ''

            deployment = Deployment(uuid=uuid,
                                    creation_time=rs_json['creationTime'],
                                    update_time=rs_json['updateTime'],
                                    physicalId=vphid,
                                    description=additionaldescription,
                                    status=rs_json['status'],
                                    outputs=json.dumps(rs_json['outputs']),
                                    task=rs_json['task'],
                                    links=json.dumps(rs_json['links']),
                                    sub=rs_json['createdBy']['subject'],
                                    template=template_text,
                                    inputs=json.dumps(inputs),
                                    params=json.dumps(params),
                                    provider_name=providername,
                                    endpoint='',
                                    feedback_required=feedback_required,
                                    remote=1,
                                    issuer=rs_json['createdBy']['issuer'],
                                    storage_encryption=storage_encryption,
                                    vault_secret_uuid=vault_secret_uuid,
                                    vault_secret_key=vault_secret_key,
                                    elastic=elastic,
                                    upgradable=upgradable)
            db.session.add(deployment)
            db.session.commit()

        else:
            flash("Deployment with uuid:{} is already in the database!".format(uuid))

    return redirect(url_for('showdeployments'))


def create_vault_wrapping_token(access_token):
    vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience,
                             access_token, vault_secrets_path)

    auth_token = vault.get_auth_token()

    wrapping_token = vault.get_wrapping_token(vault_wrapping_token_time_duration, auth_token, vault_write_policy,
                                              vault_write_token_time_duration, vault_wtite_token_renewal_time_duration)

    return wrapping_token


@app.route('/logout')
def logout():
    session.clear()
    iam_blueprint.session.get("/logout")
    return redirect(url_for('login'))


@app.route('/callback', methods=['POST'])
def callback():
    payload = request.get_json()
    app.logger.info("Callback payload: " + json.dumps(payload))

    status = payload['status']
    task = payload['task']
    uuid = payload['uuid']
    providername = payload['cloudProviderName'] if 'cloudProviderName' in payload else ''
    status_reason = payload['statusReason'] if 'statusReason' in payload else ''
    rf = 0

    user = get_user(payload['createdBy']['subject'])
    user_email = user.email  # email

    dep = get_deployment(uuid)

    if dep is not None:

        rf = dep.feedback_required
        pn = dep.provider_name if dep.provider_name is not None else ''
        if dep.status != status or dep.task != task or pn != providername or status_reason != dep.status_reason:
            if 'endpoint' in payload['outputs']:
                dep.endpoint = payload['outputs']['endpoint']
            dep.update_time = payload['updateTime']
            if 'physicalId' in payload:
                dep.physicalId = payload['physicalId']
            dep.status = status
            dep.outputs = json.dumps(payload['outputs'])
            dep.task = task
            dep.provider_name = providername
            dep.status_reason = status_reason
            db.session.add(dep)
            db.session.commit()
    else:
        app.logger.info("Deployment with uuid:{} not found!".format(uuid))

    # send email to user
    mail_sender = app.config.get('MAIL_SENDER')
    if mail_sender and user_email != '' and rf == 1:
        if status == 'CREATE_COMPLETE':
            msg = Message("Deployment complete",
                          sender=mail_sender,
                          recipients=[user_email])
            msg.body = "Your deployment request with uuid: {} has been successfully completed.".format(uuid)
            try:
                mail.send(msg)
            except Exception as error:
                logexception("sending email:".format(error))

        if status == 'CREATE_FAILED':
            msg = Message("Deployment failed",
                          sender=mail_sender,
                          recipients=[user_email])
            msg.body = "Your deployment request with uuid: {} has failed.".format(uuid)
            try:
                mail.send(msg)
            except Exception as error:
                logexception("sending email:".format(error))

    resp = make_response('')
    resp.status_code = 200
    resp.mimetype = 'application/json'

    return resp


@app.route('/read_secret_from_vault/<depid>')
@authorized_with_valid_token
def read_secret_from_vault(depid=None):
    access_token = iam_blueprint.session.token['access_token']

    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep is None:
        return redirect(url_for('home'))
    else:

        vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience,
                                 access_token, vault_secrets_path)

        auth_token = vault.get_auth_token()
        read_token = vault.get_token(auth_token, vault_read_policy, vault_read_token_time_duration,
                                     vault_read_token_renewal_duration)

        # retrieval of secret_path and secret_key from the db goes here
        secret_path = session['userid'] + "/" + dep['vault_secret_uuid']
        user_key = dep['vault_secret_key']

        response_output = vault.read_secret(read_token, secret_path, user_key)
        vault.revoke_token(auth_token)

        return response_output


@app.route('/ssh_keys')
@authorized_with_valid_token
def ssh_keys():
    sshkey = get_ssh_pub_key()
    return render_template('ssh_keys.html', sshkey=sshkey)


def get_ssh_pub_key():
    # read database
    user = get_user(session['userid'])
    return user.sshkey


@app.route('/update_ssh_key/<subject>', methods=['POST'])
@authorized_with_valid_token
def update_ssh_key(subject):
    # access_token = iam_blueprint.session.token['access_token']

    sshkey = request.form['sshkey']
    if str(check_ssh_key(sshkey.encode())) != "0":
        flash("Invaild SSH public key. Please insert a correct one.", 'warning')
        return redirect(url_for('ssh_keys'))

    # update database
    user = get_user(subject)
    user.sshkey = sshkey
    db.session.add(user)
    db.session.commit()

    return redirect(url_for('ssh_keys'))


def check_ssh_key(key):
    # credits to: https://gist.github.com/piyushbansal/5243418

    array = key.split()

    # Each rsa-ssh key has 3 different strings in it, first one being
    # typeofkey second one being keystring third one being username .
    if len(array) != 3:
        return 1

    typeofkey = array[0]
    string = array[1]
    # username = array[2]

    # must have only valid rsa-ssh key characters ie binascii characters
    try:
        data = base64.decodebytes(string)
    except binascii.Error:
        return 1

    a = 4
    # unpack the contents of data, from data[:4] , it must be equal to 7 , property of ssh key .
    try:
        str_len = struct.unpack('>I', data[:a])[0]
    except struct.error:
        return 1

    # data[4:11] must have string which matches with the typeofkey , another ssh key property.
    if data[a:a + str_len] == typeofkey and int(str_len) == int(7):
        return 0
    else:
        return 1


@app.route('/delete_ssh_key/<subject>')
@authorized_with_valid_token
def delete_ssh_key(subject):
    user = get_user(subject)
    user.sshkey = None
    db.session.add(user)
    db.session.commit()

    access_token = iam_blueprint.session.token['access_token']
    privkey_key = session['userid'] + '/ssh_private_key'
    delete_secret_from_vault(access_token, privkey_key)

    return redirect(url_for('ssh_keys'))


@app.route('/create_ssh_key/<subject>')
@authorized_with_valid_token
def create_ssh_key(subject):
    access_token = iam_blueprint.session.token['access_token']
    privkey, pubkey = generate_ssh_key()
    privkey = privkey.decode("utf-8").replace("\n", "\\n")
    store_privkey_to_vault(access_token, privkey)

    # update database
    user = get_user(subject)
    user.sshkey = pubkey.decode("utf-8")
    db.session.add(user)
    db.session.commit()

    return redirect(url_for('ssh_keys'))


def generate_ssh_key():
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend as crypto_default_backend

    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption())
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )

    return private_key, public_key


def store_privkey_to_vault(access_token, privkey_value):
    vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience,
                             access_token, vault_secrets_path)
    auth_token = vault.get_auth_token()
    write_token = vault.get_token(auth_token, vault_write_policy, vault_write_token_time_duration,
                                  vault_wtite_token_renewal_time_duration)

    secret_path = session['userid'] + '/ssh_private_key'
    privkey_key = 'ssh_private_key'

    response_output = vault.write_secret(write_token, secret_path, privkey_key, privkey_value)
    vault.revoke_token(auth_token)

    return response_output


@app.route('/read_privkey_from_vault/<subject>')
@authorized_with_valid_token
def read_privkey_from_vault(subject):
    access_token = iam_blueprint.session.token['access_token']
    vault = VaultIntegration(vault_url, iam_base_url, iam_client_id, iam_client_secret, vault_bound_audience,
                             access_token, vault_secrets_path)
    auth_token = vault.get_auth_token()
    read_token = vault.get_token(auth_token, vault_read_policy, vault_read_token_time_duration,
                                 vault_read_token_renewal_duration)

    secret_path = session['userid'] + '/ssh_private_key'
    privkey_key = 'ssh_private_key'

    response_output = vault.read_secret(read_token, secret_path, privkey_key)
    vault.revoke_token(auth_token)

    return response_output


@app.route('/get_monitoring_info')
@authorized_with_valid_token
def get_monitoring_info():
    provider = request.args.get('provider', None)
    serviceid = request.args.get('service_id', None)
    # servicetype = request.args.get('service_type',None)

    access_token = iam_blueprint.session.token['access_token']

    headers = {'Authorization': 'bearer %s' % access_token}
    url = settings.orchestratorConf[
              'monitoring_url'] + "/monitoring/adapters/zabbix/zones/indigo/types/infrastructure/groups/" + \
          provider + "/hosts/" + serviceid
    response = requests.get(url, headers=headers)

    monitoring_data = {}

    if response.ok:
        try:
            monitoring_data = response.json()['result']['groups'][0]['paasMachines'][0]['services'][0]['paasMetrics']
        except Exception as e:
            app.logger.debug("Error getting monitoring data")

    return render_template('monitoring_metrics.html', monitoring_data=monitoring_data)
