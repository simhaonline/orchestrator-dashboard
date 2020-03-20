from flask import Blueprint, session, render_template, flash, redirect, url_for, json, request
from app import app, iam_blueprint, settings, db, tosca
from app.utils import auth
from app.models.Deployment import Deployment
from app.models.User import User
from app.models import helpers as models_helpers
from app.providers import sla
from app.extensions.flask_tosca import helpers as tosca_helpers
from packaging import version
import uuid as uuid_generator
import requests
import yaml
import io

deployments_bp = Blueprint('deployments_bp', __name__,
                           template_folder='templates',
                           static_folder='static'
                           )

iam_base_url = settings.iamUrl
iam_client_id = settings.iamClientID
iam_client_secret = settings.iamClientSecret

issuer = settings.iamUrl
if not issuer.endswith('/'):
    issuer += '/'

@deployments_bp.route('/all')
@auth.authorized_with_valid_token
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
        result = models_helpers.updatedeploymentsstatus(deployments, session['userid'])
        deployments = result['deployments']
        app.logger.debug("Deployments: " + str(deployments))

        deployments_uuid_array = result['iids']
        session['deployments_uuid_array'] = deployments_uuid_array

    return render_template('deployments.html', deployments=deployments)


@deployments_bp.route('/<depid>/template')
@auth.authorized_with_valid_token
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


@deployments_bp.route('/<depid>/lock')
@auth.authorized_with_valid_token
def lockdeployment(depid=None):
    dep = Deployment.get_deployment(depid)
    if dep is not None:
        dep.locked = 1
        db.session.add(dep)
        db.session.commit()
    return redirect(url_for('deployments_bp.showdeployments'))


@deployments_bp.route('/<depid>/unlock')
@auth.authorized_with_valid_token
def unlockdeployment(depid=None):
    dep = Deployment.get_deployment(depid)
    if dep is not None:
        dep.locked = 0
        db.session.add(dep)
        db.session.commit()
    return redirect(url_for('deployments_bp.showdeployments'))


@deployments_bp.route('/<depid>/outputs')
@auth.authorized_with_valid_token
def depoutput(depid=None):
    if not session['userrole'].lower() == 'admin' and depid not in session['deployments_uuid_array']:
        flash("You are not allowed to browse this page!")
        return redirect(url_for('deployments_bp.showdeployments'))

    # retrieve deployment from DB
    dep = Deployment.get_deployment(depid)
    if dep is None:
        return redirect(url_for('home'))
    else:
        inputs = json.loads(dep.inputs.strip('\"')) if dep.inputs else {}
        outputs = json.loads(dep.outputs.strip('\"')) if dep.outputs else {}

        return render_template('depoutput.html',
                               deployment=dep,
                               inputs=inputs,
                               outputs=outputs)


@deployments_bp.route('/<depid>/template')
def deptemplatedb(depid):
    if not iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    # retrieve deployment from DB
    dep = Deployment.get_deployment(depid)
    if dep is None:
        return redirect(url_for('home'))
    else:
        template = dep.template
        return render_template('deptemplate.html', template=template)


@deployments_bp.route('/<physicalId>/log')
@auth.authorized_with_valid_token
def deplog(physicalId=None):
    access_token = iam_blueprint.session.token['access_token']
    headers = {'Authorization': 'id = im; type = InfrastructureManager; token = %s;' % access_token}

    app.logger.debug("Configuration: " + json.dumps(settings.orchestratorConf))

    url = settings.orchestratorConf['im_url'] + "/infrastructures/" + physicalId + "/contmsg"
    response = requests.get(url, headers=headers)

    log = "Not found" if not response.ok else response.text
    return render_template('deplog.html', log=log)


@deployments_bp.route('/<depid>/delete')
@auth.authorized_with_valid_token
def depdel(depid=None):
    access_token = iam_blueprint.session.token['access_token']
    headers = {'Authorization': 'bearer %s' % access_token}
    url = settings.orchestratorUrl + "/deployments/" + depid
    response = requests.delete(url, headers=headers)

    if not response.ok:
        flash("Error deleting deployment: " + response.text)
    else:
        dep = Deployment.get_deployment(depid)
        if dep is not None and dep.storage_encryption == 1:
            secret_path = session['userid'] + "/" + dep.vault_secret_uuid
            delete_secret_from_vault(access_token, secret_path)

    return redirect(url_for('deployments_bp.showdeployments'))


@app.route('/depupdate/<depid>')
@auth.authorized_with_valid_token
def depupdate(depid=None):
    if depid is not None:
        dep = Deployment.get_deployment(depid)
        if dep is not None:
            access_token = iam_blueprint.session.token['access_token']
            template = dep.template
            tosca_info = tosca.extracttoscainfo(yaml.full_load(io.StringIO(template)), None, None, None)
            sla_id = tosca_helpers.getslapolicy(tosca_info)
            slas = sla.get_slas(access_token, settings.orchestratorConf['slam_url'],
                                settings.orchestratorConf['cmdb_url'])
            ssh_pub_key = User.get_ssh_pub_key(session['userid'])

            return render_template('depupdate.html',
                                   template=template,
                                   template_description=tosca_info['description'],
                                   instance_description=dep.description,
                                   feedback_required=dep.feedback_required,
                                   keep_last_attempt=dep.keep_last_attempt,
                                   provider_timeout=app.config['PROVIDER_TIMEOUT'],
                                   selectedTemplate=tosca_info,
                                   ssh_pub_key=ssh_pub_key,
                                   slas=slas,
                                   sla_id=sla_id,
                                   depid=depid)

    return redirect(url_for('deployments_bp.showdeployments'))


@app.route('/updatedep', methods=['POST'])
@auth.authorized_with_valid_token
def updatedep():

    access_token = iam_blueprint.session.token['access_token']

    form_data = request.form.to_dict()

    app.logger.debug("Form data: " + json.dumps(form_data))

    template_text = form_data['template']
    template = yaml.full_load(io.StringIO(template_text))

    depid = form_data['depid']
    dep = Deployment.get_deployment(depid)

    params = {}

    keep_last_attempt = params['keepLastAttempt'] = 'true' if 'extra_opts.keepLastAttempt' in form_data \
        else dep.keep_last_attempt
    feedback_required = 1 if 'extra_opts.sendEmailFeedback' in form_data else dep.feedback_required
    params['providerTimeoutMins'] = form_data[
        'extra_opts.providerTimeout'] if 'extra_opts.providerTimeoutSet' in form_data else app.config[
        'PROVIDER_TIMEOUT']
    params['timeoutMins'] = app.config['OVERALL_TIMEOUT']
    params['callback'] = app.config['CALLBACK_URL']

    if form_data['extra_opts.schedtype'].lower() == "man":
        template = add_sla_to_template(template, form_data['extra_opts.selectedSLA'])
    else:
        remove_sla_from_template(template)

    additionaldescription = form_data['additional_description']

    inputs = json.loads(dep.inputs)

    if additionaldescription is not None:
        inputs['additional_description'] = additionaldescription

    app.logger.debug("Parameters: " + json.dumps(inputs))

    payload = {"template": yaml.dump(template, default_flow_style=False, sort_keys=False),
               "parameters": inputs}
    payload.update(params)

    url = settings.orchestratorUrl + "/deployments/" + depid
    headers = {'Content-Type': 'application/json', 'Authorization': 'bearer %s' % access_token}
    response = requests.put(url, json=payload, headers=headers)

    if not response.ok:
        flash("Error updating deployment: \n" + response.text)
    else:
        # store data into database
        dep.keep_last_attempt = keep_last_attempt
        dep.feedback_required = feedback_required
        dep.description = additionaldescription
        dep.template = template_text
        db.session.add(dep)
        db.session.commit()

    return redirect(url_for('deployments_bp.showdeployments'))


@app.route('/configure')
@auth.authorized_with_valid_token
def configure():
    access_token = iam_blueprint.session.token['access_token']

    selected_tosca = request.args['selected_tosca']

    template = tosca.tosca_info[selected_tosca]
    sla_id = tosca_helpers.getslapolicy(template)

    slas = sla.get_slas(access_token, settings.orchestratorConf['slam_url'], settings.orchestratorConf['cmdb_url'],
                        template["deployment_type"])

    ssh_pub_key = User.get_ssh_pub_key(session['userid'])

    return render_template('createdep.html',
                           template=template,
                           feedback_required=True,
                           keep_last_attempt=False,
                           provider_timeout=app.config['PROVIDER_TIMEOUT'],
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
@auth.authorized_with_valid_token
def createdep():
    access_token = iam_blueprint.session.token['access_token']

    app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

    with io.open(tosca.tosca_dir + request.args.get('template')) as stream:
        template = yaml.full_load(stream)
        # rewind file
        stream.seek(0)
        template_text = stream.read()

        form_data = request.form.to_dict()

        params = {}

        keep_last_attempt = 1 if 'extra_opts.keepLastAttempt' in form_data else 0
        params['keepLastAttempt'] = 'true' if 'extra_opts.keepLastAttempt' in form_data else 'false'
        feedback_required = 1 if 'extra_opts.sendEmailFeedback' in form_data else 0
        params['providerTimeoutMins'] = form_data[
            'extra_opts.providerTimeout'] if 'extra_opts.providerTimeoutSet' in form_data else app.config[
            'PROVIDER_TIMEOUT']
        params['timeoutMins'] = app.config['OVERALL_TIMEOUT']
        params['callback'] = app.config['CALLBACK_URL']

        if form_data['extra_opts.schedtype'].lower() == "man":
            template = add_sla_to_template(template, form_data['extra_opts.selectedSLA'])
        else:
            remove_sla_from_template(template)

        feedback_required = 1 if 'extra_opts.sendEmailFeedback' in form_data else 0

        additionaldescription = form_data['additional_description']

        inputs = {k: v for (k, v) in form_data.items() if not k.startswith("extra_opts.")}

        storage_encryption, vault_secret_uuid, vault_secret_key = add_storage_encryption(access_token, inputs)

        if 'instance_key_pub' in inputs and inputs['instance_key_pub'] == '':
            inputs['instance_key_pub'] = User.get_ssh_pub_key(session['userid'])

        app.logger.debug("Parameters: " + json.dumps(inputs))

        payload = {"template": yaml.dump(template, default_flow_style=False, sort_keys=False),
                   "parameters": inputs}
        # set additional params
        payload.update(params)

        elastic = tosca_helpers.eleasticdeployment(template)
        updatable = tosca_helpers.updatabledeployment(template)

    url = settings.orchestratorUrl + "/deployments/"
    headers = {'Content-Type': 'application/json', 'Authorization': 'bearer %s' % access_token}
    response = requests.post(url, json=payload, headers=headers)

    if not response.ok:
        flash("Error submitting deployment: \n" + response.text)
    else:
        # store data into database
        rs_json = json.loads(response.text)
        uuid = rs_json['uuid']
        deployment = Deployment.get_deployment(uuid)
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
                                    keep_last_attempt=keep_last_attempt,
                                    remote=1,
                                    issuer=rs_json['createdBy']['issuer'],
                                    storage_encryption=storage_encryption,
                                    vault_secret_uuid=vault_secret_uuid,
                                    vault_secret_key=vault_secret_key,
                                    elastic=elastic,
                                    updatable=updatable)
            db.session.add(deployment)
            db.session.commit()

        else:
            flash("Deployment with uuid:{} is already in the database!".format(uuid))

    return redirect(url_for('deployments_bp.showdeployments'))



def delete_secret_from_vault(access_token, secret_path):
    vault_url = app.config.get('VAULT_URL')

    vault_secrets_path = app.config.get('VAULT_SECRETS_PATH')
    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_delete_policy = app.config.get("DELETE_POLICY")
    vault_delete_token_time_duration = app.config.get("DELETE_TOKEN_TIME_DURATION")
    vault_delete_token_renewal_time_duration = app.config.get("DELETE_TOKEN_RENEWAL_TIME_DURATION")
    vault_role = app.config.get("VAULT_ROLE")

    jwt_token = auth.exchange_token_with_audience(iam_base_url,
                                                  iam_client_id, iam_client_secret, access_token,
                                                  vault_bound_audience)

    vault_client = app.vault.VaultClient(vault_url, jwt_token, vault_role)


    delete_token = vault_client.get_token(vault_delete_policy, vault_delete_token_time_duration,
                                   vault_delete_token_renewal_time_duration)

    vault_client.delete_secret(delete_token, secret_path)


def add_storage_encryption(access_token, inputs):
    vault_url = app.config.get('VAULT_URL')
    vault_bound_audience = app.config.get('VAULT_BOUND_AUDIENCE')
    vault_role = app.config.get("VAULT_ROLE")
    vault_wrapping_token_time_duration = app.config.get("WRAPPING_TOKEN_TIME_DURATION")
    vault_write_policy = app.config.get("WRITE_POLICY")
    vault_write_token_time_duration = app.config.get("WRITE_TOKEN_TIME_DURATION")
    vault_write_token_renewal_time_duration = app.config.get("WRITE_TOKEN_RENEWAL_TIME_DURATION")

    storage_encryption = 0
    vault_secret_uuid = ''
    vault_secret_key = ''
    if 'storage_encryption' in inputs and inputs['storage_encryption'].lower() == 'true':
        storage_encryption = 1
        vault_secret_key = 'secret'

    if storage_encryption == 1:
        inputs['vault_url'] = app.config.get('VAULT_URL')
        vault_secret_uuid = str(uuid_generator.uuid4())
        if 'vault_secret_key' in inputs:
            vault_secret_key = inputs['vault_secret_key']
        app.logger.debug("Storage encryption enabled, appending wrapping token.")

        jwt_token = auth.exchange_token_with_audience(iam_base_url,
                                                      iam_client_id, iam_client_secret, access_token,
                                                      vault_bound_audience)

        vault_client = app.vault.VaultClient(vault_url, jwt_token, vault_role)

        wrapping_token = vault_client.get_wrapping_token(vault_wrapping_token_time_duration, jwt_token, vault_write_policy,
                                                  vault_write_token_time_duration,
                                                  vault_write_token_renewal_time_duration)

        inputs['vault_wrapping_token'] = wrapping_token
        inputs['vault_secret_path'] = session['userid'] + '/' + vault_secret_uuid

    return storage_encryption, vault_secret_uuid, vault_secret_key