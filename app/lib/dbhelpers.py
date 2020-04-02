from app import app, iam_blueprint, db
from . import settings
import requests
from dateutil import parser
from app.models.Deployment import Deployment
from app.models.User import User
from flask import json
import datetime


def add_object(object):
    db.session.add(object)
    db.session.commit()


def get_user(subject):
    return User.query.get(subject)


def get_users():
    users = User.query.order_by(User.family_name.desc(), User.given_name.desc()).all()
    return users


def update_user(subject, data):
    User.query.filter_by(sub=subject).update(data)
    db.session.commit()


def get_ssh_pub_key(subject):
    user = User.query.get(subject)
    return user.sshkey


def delete_ssh_key(subject):
    User.query.get(subject).sshkey = None
    db.session.commit()


def update_deployment(depuuid, data):
    Deployment.query.filter_by(uuid=depuuid).update(data)
    db.session.commit()


def get_user_deployments(user_sub):
    return Deployment.query.filter_by(sub=user_sub).all()


def get_deployment(uuid):
    return Deployment.query.get(uuid)


def updatedeploymentsstatus(deployments, userid):
    result = {}
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
                                    selected_template='',
                                    inputs='',
                                    stinputs='',
                                    params='',
                                    provider_name=providername,
                                    endpoint=endpoint,
                                    remote=1,
                                    locked=0,
                                    feedback_required=0,
                                    keep_last_attempt=0,
                                    issuer=dep_json['createdBy']['issuer'],
                                    storage_encryption=0,
                                    vault_secret_uuid='',
                                    vault_secret_key='',
                                    elastic=0,
                                    updatable=0)

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

    result['deployments'] = deps
    result['iids'] = iids
    return result


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
                            selected_template=d.selected_template,
                            inputs=json.loads(
                                d.inputs.replace("\n", "\\n")) if (d.inputs is not None and d.inputs is not '') else '',
                            stinputs=json.loads(
                                d.stinputs.replace("\n", "\\n")) if (d.stinputs is not None and d.stinputs is not '') else '',
                            params=d.params,
                            provider_name='' if d.provider_name is None else d.provider_name,
                            endpoint=d.endpoint,
                            remote=d.remote,
                            locked=d.locked,
                            issuer=d.issuer,
                            feedback_required=d.feedback_required,
                            keep_last_attempt=d.keep_last_attempt,
                            storage_encryption=d.storage_encryption,
                            vault_secret_uuid='' if d.vault_secret_uuid is None else d.vault_secret_uuid,
                            vault_secret_key='' if d.vault_secret_key is None else d.vault_secret_key,
                            elastic=d.elastic,
                            updatable=d.updatable)
    return deployment
