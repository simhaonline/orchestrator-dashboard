import app
from flask import json, render_template, request, redirect, url_for, flash, session, make_response
from flask_mail import Message
import requests
import json
import datetime
import yaml
import io
import os
import linecache
import sys
from fnmatch import fnmatch
from hashlib import md5
import mysql.connector
from dateutil import parser

iam_base_url = app.app.config['IAM_BASE_URL']
issuer = iam_base_url
if not issuer.endswith('/'):
    issuer += '/'
db_host = app.app.config['DB_HOST']
db_port = app.app.config['DB_PORT']
db_user = app.app.config['DB_USER']
db_password = app.app.config['DB_PASSWORD']
db_name = app.app.config['DB_NAME']


def to_pretty_json(value):
    return json.dumps(value, sort_keys=True,
                      indent=4, separators=(',', ': '))


app.app.jinja_env.filters['tojson_pretty'] = to_pretty_json


def avatar(email, size):
    digest = md5(email.lower().encode('utf-8')).hexdigest()
    return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(digest, size)


def getdbconnection():
    cnx = mysql.connector.connect(user=db_user,
                                  password=db_password,
                                  host=db_host,
                                  database=db_name)
    return cnx


toscaDir = app.app.config.get('TOSCA_TEMPLATES_DIR') + "/"
toscaTemplates = []
for path, subdirs, files in os.walk(toscaDir):
    for name in files:
        if fnmatch(name, "*.yml") or fnmatch(name, "*.yaml"):
            # skip hidden files
            if name[0] != '.':
                toscaTemplates.append(os.path.relpath(os.path.join(path, name), toscaDir))

orchestratorUrl = app.app.config.get('ORCHESTRATOR_URL')
slamUrl = app.app.config.get('SLAM_URL')
cmdbUrl = app.app.config.get('CMDB_URL')


@app.app.route('/settings')
def show_settings():
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))
    return render_template('settings.html', orchestrator_url=orchestratorUrl, iam_url=app.iam_base_url)


@app.app.route('/deployments/<subject>')
def show_deployments(subject):
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))
    if not session['userrole'] == 'admin':
        return render_template('home.html')

    deployments = []
    user = get_user(subject)

    if user is not {}:
        #
        # retrieve deployments from orchestrator
        access_token = app.iam_blueprint.token['access_token']

        headers = {'Authorization': 'bearer %s' % access_token}

        url = orchestratorUrl + "/deployments?createdBy={}&page={}&size={}".format('{}@{}'.format(subject, issuer), 0, 999999)
        response = requests.get(url, headers=headers)

        deporch = []
        if response.ok:
            deporch = response.json()["content"]
            deporch = updatedeploymentsstatus(deporch, subject)

        iids = []
        # make map of remote deployments
        for dep_json in deporch:
            iids.append(dep_json['uuid'])

        #
        # retrieve deployments from DB
        try:
            connection = getdbconnection()
            cursor = connection.cursor()

            select_query = "SELECT * FROM `deployments` WHERE `sub` = %s"
            cursor.execute(select_query, (user['sub'],))

            deployments = cvdeployments(cursor.fetchall())

            # update remote status
            for dep in deployments:
                remote = dep['remote']
                newremote = remote
                if not dep['uuid'] in iids:
                    if remote == 1:
                        newremote = 0
                else:
                    if remote == 0:
                        newremote = 1
                if remote != newremote:
                    update_query = "UPDATE `deployments` SET `remote` = '{}' WHERE `uuid` = '{}'"
                    update_cmd = update_query.format(newremote, dep['uuid'])
                    cursor.execute(update_cmd)
                    connection.commit()

        except mysql.connector.Error as error:
            logexception("reading deployments table: {}".format(error))
        except Exception as ex:
            logexception("reading deployments: {}".format(ex))
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

        return render_template('dep_user.html', user=user, deployments=deployments)
    else:
        flash("User not found!")
        users = get_users()
        return render_template('users.html', users=users)


@app.app.route('/user/<subject>', methods=['GET', 'POST'])
def show_user(subject):
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))
    if not session['userrole'] == 'admin':
        return render_template('home.html')

    if request.method == 'POST':
        # cannot change its own role
        if session['userid'] == subject:
            role = session['userrole']
        else:
            role = request.form['role']
        active = request.form['active']
        # update database
        try:
            connection = getdbconnection()
            cursor = connection.cursor()

            update_query = "UPDATE `users` SET `role` = '{}', `active` = '{}' WHERE `sub` = '{}'"
            update_cmd = update_query.format(role, active, subject)
            cursor.execute(update_cmd)
            connection.commit()
        except mysql.connector.Error as error:
            logexception("updating users table {}".format(error))
        finally:
            if connection.is_connected():
                cursor.close()
                connection.close()

    user = get_user(subject)
    if user is not None:
        return render_template('user.html', user=user)
    else:
        return render_template('home.html')


def get_users():
    users = []
    try:
        connection = getdbconnection()
        cursor = connection.cursor()

        # WHERE `active` = '1'
        select_query = "SELECT * FROM `users` ORDER BY `family_name`,`given_name`"
        cursor.execute(select_query)
        u = cursor.fetchall()
        for tp in u:
            users.append(cvuser(tp))
    except mysql.connector.Error as error:
        logexception("reading users table {}".format(error))
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    return users


def get_user(subject):
    user = {}
    try:
        connection = getdbconnection()
        cursor = connection.cursor()

        select_query = "SELECT * FROM `users` WHERE `sub` = %s"
        cursor.execute(select_query, (subject,))
        u = cursor.fetchone()
        if cursor.rowcount == 1:
            user = cvuser(u)
    except mysql.connector.Error as error:
        logexception("reading users table {}".format(error))
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
    return user


def get_deployment(uuid):
    deployment = {}
    try:
        connection = getdbconnection()
        cursor = connection.cursor()

        select_query = "SELECT * FROM `deployments` WHERE `uuid` = %s"
        cursor.execute(select_query, (uuid,))

        r = cursor.fetchone()
        if cursor.rowcount == 1:
            deployment = cvdeployment(r)

    except mysql.connector.Error as error:
        logexception("reading deployments table: {}".format(error))
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

    return deployment


@app.app.route('/users')
def show_users():
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))
    if not session['userrole'] == 'admin':
        return render_template('home.html')

    users = get_users()

    return render_template('users.html', users=users)


@app.app.route('/login')
def login():
    session.clear()
    return render_template('home.html')


def get_sla_extra_info(access_token, service_id):
    headers = {'Authorization': 'bearer %s' % access_token}
    url = cmdbUrl + "/service/id/" + service_id
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()
    app.app.logger.info(json.dumps(response.json()['data']['service_type']))

    service_type = response.json()['data']['service_type']
    sitename = response.json()['data']['sitename']
    if 'properties' in response.json()['data']:
        if 'gpu_support' in response.json()['data']['properties']:
            service_type = service_type + " (gpu_support: " + str(
                response.json()['data']['properties']['gpu_support']) + ")"

    return sitename, service_type


def get_slas(access_token):
    headers = {'Authorization': 'bearer %s' % access_token}
    url = slamUrl + "/rest/slam/preferences/" + session['organisation_name']
    response = requests.get(url, headers=headers, timeout=20)
    app.app.logger.info("SLA response status: " + str(response.status_code))

    response.raise_for_status()
    app.app.logger.info("SLA response: " + json.dumps(response.json()))
    slas = response.json()['sla']

    for i in range(len(slas)):
        sitename, service_type = get_sla_extra_info(access_token, slas[i]['services'][0]['service_id'])
        slas[i]['service_type'] = service_type
        slas[i]['sitename'] = sitename

    return slas


@app.app.route('/slas')
def getslas():
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    try:
        access_token = app.iam_blueprint.token['access_token']
        slas = get_slas(access_token)

    except Exception as e:
        flash("Error retrieving SLAs list: \n" + str(e), 'warning')
        return redirect(url_for('home'))

    return render_template('sla.html', slas=slas)


def cvdeployments(listt):
    deployments = []
    for tp in listt:
        deployments.append(cvdeployment(tp))

    return deployments


def cvdeployment(tp):
    deployment = {}
    deployment['uuid'] = tp[0]
    deployment['creationTime'] = tp[1]
    deployment['updateTime'] = tp[2]
    if not tp[3] is None:
        deployment['physicalId'] = tp[3]
    else:
        deployment['physicalId'] = ''
    deployment['additionaldescription'] = tp[4]
    deployment['status'] = tp[5]
    if not tp[6] is None and not tp[6] is '':
        deployment['outputs'] = json.loads(tp[6].replace("\n", "\\n"))
    else:
        deployment['outputs'] = ''
    deployment['task'] = tp[7]
    if not tp[8] is None and not tp[8] is '':
        deployment['links'] = json.loads(tp[8].replace("\n", "\\n"))
    else:
        deployment['links'] = ''
    createdby = {}
    createdby['issuer'] = tp[18]
    createdby['subject'] = tp[9]
    deployment['createdBy'] = createdby
    if not tp[10] is None:
        deployment['cloudProviderName'] = tp[10]
    else:
        deployment['cloudProviderName'] = ''
    deployment['endpoint'] = tp[11]
    deployment['template'] = tp[12]
    if not tp[13] is None and not tp[13] is '':
        deployment['inputs'] = json.loads(tp[13].replace("\n", "\\n"))
    else:
        deployment['inputs'] = ''
    deployment['locked'] = tp[15]
    deployment['feedbackrequired'] = tp[16]
    deployment['remote'] = tp[17]
    return deployment


def cvuser(tp):
    user = {}
    user['sub'] = tp[0]
    user['name'] = tp[1]
    user['username'] = tp[2]
    user['given_name'] = tp[3]
    user['family_name'] = tp[4]
    user['email'] = tp[5]
    user['organisation_name'] = tp[6]
    user['picture'] = tp[7]
    user['role'] = tp[8]
    user['active'] = tp[9]
    return user


def updatedeploymentsstatus(deployments, userid):
    iids = []
    uuid = ''
    # update deployments status in database
    for dep_json in deployments:
        uuid = dep_json['uuid']
        iids.append(uuid)

        # sanitize date
        dt = parser.parse(dep_json['creationTime'])
        dep_json['creationTime'] = dt.strftime("%Y-%m-%d %H:%M:%S")
        dt = parser.parse(dep_json['updateTime'])
        dep_json['updateTime'] = dt.strftime("%Y-%m-%d %H:%M:%S")
        if 'cloudProviderName' in dep_json:
            providername = dep_json['cloudProviderName']
        else:
            providername = ''

        dep = get_deployment(uuid)

        if 'cloudProviderName' in dep:
            pn = dep['cloudProviderName']
        else:
            pn = ''
        if dep != {}:
            dep_json['additionaldescription'] = dep['additionaldescription']
            dep_json['endpoint'] = dep['endpoint']

        if (dep != {} and (dep['status'] != dep_json['status'] or pn != providername)) or dep == {}:
            try:
                connection = getdbconnection()
                cursor = connection.cursor()

                if 'physicalId' in dep_json:
                    vphid = dep_json['physicalId']
                else:
                    vphid = ''

                if dep != {}:
                    update_query = "UPDATE `deployments` SET `update_time` = '{}', `physicalId` = '{}', `status` = '{}', `outputs` = '{}', `task` = '{}', `links` = '{}', `remote` = '{}' , `provider_name` = '{}' WHERE `uuid` = '{}'"
                    update_cmd = update_query.format(dep_json['updateTime'], vphid, dep_json['status'],
                                                     json.dumps(dep_json['outputs']), dep_json['task'],
                                                     json.dumps(dep_json['links']), '1', providername, uuid)
                    cursor.execute(update_cmd)
                    connection.commit()
                else:
                    app.app.logger.info("Deployment with uuid:{} not found!".format(uuid))

                    # retrieve template
                    access_token = app.iam_blueprint.session.token['access_token']
                    headers = {'Authorization': 'bearer %s' % access_token}

                    url = orchestratorUrl + "/deployments/" + uuid + "/template"
                    response = requests.get(url, headers=headers)

                    if not response.ok:
                        template = ''
                    else:
                        template = response.text

                    # insert missing deployment in database
                    if 'endpoint' in dep_json['outputs']:
                        endpoint = dep_json['outputs']['endpoint']
                    else:
                        endpoint = ''
                    insert_query = "INSERT INTO `deployments` (`uuid`, `creation_time`, `update_time`, `physicalId`, `description`, `status`, `outputs`, `task`, `links`, `sub`, `template`, `inputs`, `params`, `provider_name`, `endpoint`, `remote`, `issuer`)" \
                                   " VALUES  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    insert_values = (
                        uuid, dep_json['creationTime'], dep_json['updateTime'], vphid, '', dep_json['status'],
                        json.dumps(dep_json['outputs']), dep_json['task'], json.dumps(dep_json['links']),
                        userid, template, '', '', providername, endpoint, '1', dep_json['createdBy']['issuer'])
                    cursor.execute(insert_query, insert_values)
                    connection.commit()

            except mysql.connector.Error as error:
                connection.rollback()  # rollback if any exception occured
                logexception("updating deployment with uuid:{} in deployments table: {}".format(uuid, error))
            finally:
                if connection.is_connected():
                    cursor.close()
                    connection.close()
    #
    # check delete in progress or missing
    try:
        uuid = ''
        connection = getdbconnection()
        cursor = connection.cursor()

        select_query = "SELECT * FROM `deployments` WHERE `sub` = %s AND `status` = 'DELETE_IN_PROGRESS'"
        cursor.execute(select_query, (userid,))

        records = cursor.fetchall()
        for r in records:
            uuid = r[0]
            if uuid not in iids:
                time_string = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                update_query = "UPDATE `deployments` SET `update_time` = '{}', `status` = '{}' WHERE `uuid` = '{}'"
                update_cmd = update_query.format(time_string, 'DELETE_COMPLETE',uuid)
                cursor.execute(update_cmd)
                connection.commit()
    except mysql.connector.Error as error:
        connection.rollback()  # rollback if any exception occured
        logexception("updating deployment with UUID:{} in deployments table: {}".format(uuid, error))
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

    return deployments


def logexception(err):
    exc_type, exc_obj, tb = sys.exc_info()
    f = tb.tb_frame
    lineno = tb.tb_lineno
    filename = f.f_code.co_filename
    linecache.checkcache(filename)
    line = linecache.getline(filename, lineno, f.f_globals)
    app.app.logger.error('{} at ({}, LINE {} "{}"): {}'.format(err, filename, lineno, line.strip(), exc_obj))


@app.app.route('/dashboard/')
@app.app.route('/')
def home():
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))
    try:
        account_info = app.iam_blueprint.session.get("/userinfo")

        if account_info.ok:
            account_info_json = account_info.json()

            session['userid'] = account_info_json['sub']
            session['username'] = account_info_json['name']
            session['useremail'] = account_info_json['email']
            session['userrole'] = 'user'
            session['gravatar'] = avatar(account_info_json['email'], 26)
            session['organisation_name'] = account_info_json['organisation_name']

            # check database
            # if user not found, insert
            #
            try:
                connection = getdbconnection()
                cursor = connection.cursor()

                select_query = "SELECT * FROM `users` WHERE `sub` = %s"
                cursor.execute(select_query, (account_info_json['sub'],))
                r = cursor.fetchone()
                if cursor.rowcount != 1:
                    email = account_info_json['email']
                    admins = json.dumps(app.app.config['ADMINS'])
                    if email in admins:
                        role = 'admin'
                    else:
                        role = 'user'
                    insert_query = " INSERT INTO `users` (`sub`, `name`, `username`, `given_name`, `family_name`, `email`, `organisation_name`, `picture`, `role`, `active`)" \
                                   " VALUES  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    insert_values = (
                        account_info_json['sub'], account_info_json['name'], account_info_json['preferred_username'],
                        account_info_json['given_name'], account_info_json['family_name'], email,
                        account_info_json['organisation_name'], avatar(email, 26), role, '1')
                    cursor.execute(insert_query, insert_values)
                    connection.commit()
                else:
                    session['userrole'] = r[8]  # role
            except mysql.connector.Error as error:
                connection.rollback()  # rollback if any exception occured
                logexception("inserting record into users table {}".format(error))
            finally:
                if connection.is_connected():
                    cursor.close()
                    connection.close()
            #
            #

            access_token = app.iam_blueprint.token['access_token']

            headers = {'Authorization': 'bearer %s' % access_token}

            url = orchestratorUrl + "/deployments?createdBy=me&page={}&size={}".format(0, 999999)
            response = requests.get(url, headers=headers)

            deployments = {}
            if not response.ok:
                flash("Error retrieving deployment list: \n" + response.text, 'warning')
            else:
                deployments = response.json()["content"]
                deployments = updatedeploymentsstatus(deployments, account_info_json['sub'])

                # print(deployments)
            return render_template('deployments.html', deployments=deployments)
    except Exception as error:
        logexception(error)
        return redirect(url_for('logout'))


@app.app.route('/template/<depid>')
def deptemplate(depid=None):
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    access_token = app.iam_blueprint.session.token['access_token']
    headers = {'Authorization': 'bearer %s' % access_token}

    url = orchestratorUrl + "/deployments/" + depid + "/template"
    response = requests.get(url, headers=headers)

    if not response.ok:
        flash("Error getting template: " + response.text)
        return redirect(url_for('home'))

    template = response.text
    return render_template('deptemplate.html', template=template)
#


@app.app.route('/output/<depid>')
def depoutput(depid=None):
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home'))
    else:
        output = json.dumps(dep['outputs']).lstrip().replace("\\n", "\n")
        p = output.find('"token": "')
        if p != -1:
            p += 10
            output = output[:p] + '\n' + output[p:]
        inp = json.dumps(dep['inputs'])
        links = json.dumps(dep['links'])
        return render_template('depoutput.html', input=inp, output=output, links=links)


@app.app.route('/templatedb/<depid>')
def deptemplatedb(depid):
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    # retrieve deployment from DB
    dep = get_deployment(depid)
    if dep == {}:
        return redirect(url_for('home'))
    else:
        template = dep['template']
        return render_template('deptemplate.html', template=template)


@app.app.route('/delete/<depid>')
def depdel(depid=None):
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    access_token = app.iam_blueprint.session.token['access_token']
    headers = {'Authorization': 'bearer %s' % access_token}
    url = orchestratorUrl + "/deployments/" + depid
    response = requests.delete(url, headers=headers)

    if not response.ok:
        flash("Error deleting deployment: " + response.text)

    return redirect(url_for('home'))


@app.app.route('/create', methods=['GET', 'POST'])
def depcreate():
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    access_token = app.iam_blueprint.session.token['access_token']

    if request.method == 'GET':
        return render_template('createdep.html', templates=toscaTemplates, inputs={})
    else:
        selected_tosca = request.form.get('tosca_template')

        with io.open(toscaDir + selected_tosca) as stream:
            template = yaml.load(stream)
            if 'topology_template' not in template:
                flash(
                    "Error reading template \"" + selected_tosca + "\": syntax is not correct. Please select another template.")
                return redirect(url_for('depcreate'))

            inputs = {}
            if 'inputs' in template['topology_template']:
                inputs = template['topology_template']['inputs']

            description = "N/A"
            if 'description' in template:
                description = template['description']

            slas = get_slas(access_token)
            return render_template('createdep.html', templates=toscaTemplates, selectedTemplate=selected_tosca,
                                   description=description, inputs=inputs, slas=slas)


def add_sla_to_template(template, sla_id):
    # Add the placement policy

    # nodes = template['topology_template']['node_templates']
    # compute_nodes = []
    #    for key, dict in nodes.items():
    #        node_type=dict["type"]
    #        if node_type == "tosca.nodes.indigo.Compute" or node_type == "tosca.nodes.indigo.Container.Application.Docker.Chronos" :
    #            compute_nodes.append(key)
    #    template['topology_template']['policies']=[{ "deploy_on_specific_site": { "type": "tosca.policies.Placement", "properties": { "sla_id": sla_id }, "targets": compute_nodes  } }]
    template['topology_template']['policies'] = [
        {"deploy_on_specific_site": {"type": "tosca.policies.Placement", "properties": {"sla_id": sla_id}}}]
    app.app.logger.info(yaml.dump(template, default_flow_style=False))
    return template


@app.app.route('/submit', methods=['POST'])
def createdep():
    if not app.iam_blueprint.session.authorized:
        return redirect(url_for('login'))

    access_token = app.iam_blueprint.session.token['access_token']
    callback_url = app.app.config['CALLBACK_URL']

    app.app.logger.debug("Form data: " + json.dumps(request.form.to_dict()))

    try:
        with io.open(toscaDir + request.args.get('template')) as stream:
            template = yaml.load(stream)
            # rewind file
            stream.seek(0)
            template_text = stream.read()

            form_data = request.form.to_dict()

            params = {}
            if 'extra_opts.keepLastAttempt' in form_data:
                params['keepLastAttempt'] = 'true'
            else:
                params['keepLastAttempt'] = 'false'

            if 'extra_opts.sendEmailFeedback' in form_data:
                feedback_required = 1
            else:
                feedback_required = 0

            if form_data['extra_opts.schedtype'] == "man":
                template = add_sla_to_template(template, form_data['extra_opts.selectedSLA'])

            additionaldescription = form_data['additional_description']

            inputs = {k: v for (k, v) in form_data.items() if not k.startswith("extra_opts.")}

            app.app.logger.debug("Parameters: " + json.dumps(inputs))

            payload = {"template": yaml.dump(template, default_flow_style=False), "parameters": inputs,
                       "callback": callback_url}

        # body= json.dumps(payload)

        url = orchestratorUrl + "/deployments/"
        headers = {'Content-Type': 'application/json', 'Authorization': 'bearer %s' % access_token}
        # response = requests.post(url, data=body, headers=headers)
        response = requests.post(url, json=payload, params=params, headers=headers)

        if not response.ok:
            flash("Error submitting deployment: \n" + response.text)
        else:
            # store data into database
            rs_json = json.loads(response.text)

            try:
                connection = getdbconnection()
                cursor = connection.cursor()

                uuid = rs_json['uuid']
                select_query = "SELECT * FROM `deployments` WHERE `uuid` = %s"
                cursor.execute(select_query, (uuid,))
                cursor.fetchone()
                if cursor.rowcount != 1:
                    if 'physicalId' in rs_json:
                        vphid = rs_json['physicalId']
                    else:
                        vphid = ''
                    if 'cloudProviderName' in rs_json:
                        providername = rs_json['cloudProviderName']
                    else:
                        providername = ''

                    insert_query = "INSERT INTO `deployments` (`uuid`, `creation_time`, `update_time`, `physicalId`, `description`, `status`, `outputs`, `task`, `links`, `sub`, `template`, `inputs`, `params`, `provider_name`, `endpoint`, `feedback_required`, `remote`, `issuer`)" \
                                   " VALUES  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
                    insert_values = (
                        uuid, rs_json['creationTime'], rs_json['updateTime'], vphid, additionaldescription, rs_json['status'],
                        json.dumps(rs_json['outputs']), rs_json['task'], json.dumps(rs_json['links']),
                        rs_json['createdBy']['subject'], template_text, json.dumps(inputs), json.dumps(params),
                        providername, '', feedback_required, '1', rs_json['createdBy']['issuer'])
                    cursor.execute(insert_query, insert_values)
                    connection.commit()
                else:
                    flash("Deployment with uuid:{} is already in the database!".format(uuid))
            except mysql.connector.Error as error:
                connection.rollback()  # rollback if any exception occured
                logexception("inserting data into deployments table {}".format(error))
            finally:
                if connection.is_connected():
                    cursor.close()
                    connection.close()

        return redirect(url_for('home'))

    except Exception as e:
        flash("Error submitting deployment:" + str(e) + ". Please retry")
        return redirect(url_for('home'))


@app.app.route('/logout')
def logout():
    session.clear()
    app.iam_blueprint.session.get("/logout")
    #   del iam_blueprint.session.token
    return redirect(url_for('login'))


@app.app.route('/callback', methods=['POST'])
def callback():
    # data=request.data
    payload = request.get_json()
    app.app.logger.info("Callback payload: " + json.dumps(payload))

    status = payload['status']
    task = payload['task']
    uuid = payload['uuid']
    if 'cloudProviderName' in payload:
        providername = payload['cloudProviderName']
    else:
        providername = ''
    rf = 0

    user = get_user(payload['createdBy']['subject'])
    user_email = user['email']  # email

    dep = get_deployment(uuid)

    if dep != {}:

        st = dep['status']
        ts = dep['task']
        rf = dep['feedbackrequired']
        if 'cloudProviderName' in dep:
            pn = dep['cloudProviderName']
        else:
            pn = ''
        if st != status or ts != task or pn != providername:
            # get user from database
            try:
                connection = getdbconnection()
                cursor = connection.cursor()

                if 'physicalId' in payload:
                    vphid = payload['physicalId']
                else:
                    if 'physicalId' in dep:
                        vphid = dep['physicalId']
                    else:
                        vphid = ''
                if 'endpoint' in payload['outputs']:
                    endpoint = payload['outputs']['endpoint']
                else:
                    endpoint = dep['endpoint']
                update_query = "UPDATE `deployments` SET `update_time` = '{}', `physicalId` = '{}', `status` = '{}', `outputs` = '{}', `task` = '{}', `provider_name` = '{}', `endpoint` = '{}' WHERE `uuid` = '{}'"
                update_cmd = update_query.format(payload['updateTime'], vphid, status,
                                                 json.dumps(payload['outputs']), task, providername, endpoint, uuid)
                cursor.execute(update_cmd)
                connection.commit()
            except mysql.connector.Error as error:
                connection.rollback()  # rollback if any exception occured
                logexception("accessing database {}".format(error))
            finally:
                if connection.is_connected():
                    cursor.close()
                    connection.close()
    else:
        app.app.logger.info("Deployment with uuid:{} not found!".format(uuid))

    # send email to user
    if user_email != '' and rf == 1:
        mail_sender = app.app.config['MAIL_SENDER']
        if status == 'CREATE_COMPLETE':
            msg = Message("Deployment complete",
                          sender=mail_sender,
                          recipients=[user_email])
            msg.body = "Your deployment request with uuid: {} has been successfully completed.".format(uuid)
            try:
                app.mail.send(msg)
            except Exception as error:
                logexception("sending email:".format(error))

        if status == 'CREATE_FAILED':
            msg = Message("Deployment failed",
                          sender=mail_sender,
                          recipients=[user_email])
            msg.body = "Your deployment request with uuid: {} has failed.".format(uuid)
            try:
                app.mail.send(msg)
            except Exception as error:
                logexception("sending email:".format(error))

    resp = make_response('')
    resp.status_code = 200
    resp.mimetype = 'application/json'

    return resp
