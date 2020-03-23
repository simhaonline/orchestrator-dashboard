"""
    Flask-Tosca
    :author: Marica Antonacci <marica.antonacci@ba.infn.it>
    :license: Apache
    -------------------
    Allows to load tosca templates in Flask applications.
"""

import os
import io
from fnmatch import fnmatch
import yaml


class ToscaInfo(object):

    def __init__(self, app=None, tosca_dir=None, tosca_params_dir=None, tosca_metadata_dir=None):
        """
        Initialize the flask extension
        :param app: flask.Flask application instance
        :param tosca_dir: the dir of the tosca templates
        :param tosca_params_dir: the dir of the params files
        :param tosca_metadata_dir: the dir of the metadata files
        """

        self.tosca_dir = tosca_dir
        self.tosca_params_dir = tosca_params_dir
        self.tosca_metadata_dir = tosca_metadata_dir
        self.tosca_info = {}
        self.tosca_templates = []

        self.app = app
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Init the extension"""
        if self.tosca_dir is None:
            self.tosca_dir = app.config['TOSCA_TEMPLATES_DIR'] + "/"
        if self.tosca_params_dir is None:
            self.tosca_params_dir = app.config.get('TOSCA_PARAMETERS_DIR')
        if self.tosca_metadata_dir is None:
            self.tosca_metadata_dir = app.config.get('TOSCA_METADATA_DIR')

        self.tosca_templates = self._loadtoscatemplates()
        self.tosca_info = self._extractalltoscainfo(self.tosca_templates)

    def _loadtoscatemplates(self):
        toscatemplates = []
        for path, subdirs, files in os.walk(self.tosca_dir):
            for name in files:
                if fnmatch(name, "*.yml") or fnmatch(name, "*.yaml"):
                    # skip hidden files
                    if name[0] != '.':
                        toscatemplates.append(os.path.relpath(os.path.join(path, name), self.tosca_dir))

        return toscatemplates

    def _extractalltoscainfo(self, tosca_templates):
        tosca_info = {}
        for tosca in tosca_templates:
            with io.open(self.tosca_dir + tosca) as stream:
                template = yaml.full_load(stream)
                tosca_info[tosca] = self.extracttoscainfo(template, tosca)
        return tosca_info

    def extracttoscainfo(self, template, tosca):

        tosca_info = {
            "valid": True,
            "description": "TOSCA Template",
            "metadata": {
                "icon": "https://cdn4.iconfinder.com/data/icons/mosaicon-04/512/websettings-512.png",
                        "allowed_groups": '*'
            },
            "enable_config_form": False,
            "inputs": {},
            "node_templates": {},
            "policies": {},
            "tabs": {}
        }

        if 'topology_template' not in template:
            tosca_info["valid"] = False

        else:

            if 'description' in template:
                tosca_info["description"] = template['description']

            if 'metadata' in template and template['metadata'] is not None:
                for k, v in template['metadata'].items():
                    tosca_info["metadata"][k] = v

            if tosca and self.tosca_metadata_dir:
                tosca_metadata_path = self.tosca_metadata_dir + "/"
                for mpath, msubs, mnames in os.walk(tosca_metadata_path):
                    for mname in mnames:
                        if fnmatch(mname, os.path.splitext(tosca)[0] + '.metadata.yml') or \
                                fnmatch(mname, os.path.splitext(tosca)[0] + '.metadata.yaml'):
                            # skip hidden files
                            if mname[0] != '.':
                                tosca_metadata_file = os.path.join(mpath, mname)
                                with io.open(tosca_metadata_file) as metadata_file:
                                    metadata_template = yaml.full_load(metadata_file)

                                    if 'metadata' in metadata_template \
                                            and metadata_template['metadata'] is not None:
                                        for k, v in metadata_template['metadata'].items():
                                            tosca_info["metadata"][k] = v

            # initialize inputs
            tosca_inputs = {}
            # get inputs from template, if provided
            if 'inputs' in template['topology_template']:
                tosca_inputs = template['topology_template']['inputs']
                tosca_info['inputs'] = tosca_inputs

            if 'node_templates' in template['topology_template']:
                tosca_info['deployment_type'] = getdeploymenttype(template['topology_template']['node_templates'])

            if 'policies' in template['topology_template']:
                tosca_info['policies'] = template['topology_template']['policies']

            # add parameters code here
            if tosca and self.tosca_params_dir:
                tosca_pars_path = self.tosca_params_dir + "/"  # this has to be reassigned here because is local.
                for fpath, subs, fnames in os.walk(tosca_pars_path):
                    for fname in fnames:
                        if fnmatch(fname, os.path.splitext(tosca)[0] + '.parameters.yml') or \
                                fnmatch(fname, os.path.splitext(tosca)[0] + '.parameters.yaml'):
                            # skip hidden files
                            if fname[0] != '.':
                                tosca_pars_file = os.path.join(fpath, fname)
                                with io.open(tosca_pars_file) as pars_file:
                                    tosca_info['enable_config_form'] = True
                                    pars_data = yaml.full_load(pars_file)
                                    pars_inputs = pars_data["inputs"]
                                    tosca_info['inputs'] = {**tosca_inputs, **pars_inputs}
                                    if "tabs" in pars_data:
                                        tosca_info['tabs'] = pars_data["tabs"]
        return tosca_info


# Helper functions
def getdeploymenttype(nodes):
    deployment_type = ""
    for (j, u) in nodes.items():
        if deployment_type == "":
            for (k, v) in u.items():
                if k == "type" and v == "tosca.nodes.indigo.Compute":
                    deployment_type = "CLOUD"
                    break
                if k == "type" and v == "tosca.nodes.indigo.Container.Application.Docker.Marathon":
                    deployment_type = "MARATHON"
                    break
                if k == "type" and v == "tosca.nodes.indigo.Container.Application.Docker.Chronos":
                    deployment_type = "CHRONOS"
                    break
                if k == "type" and v == "tosca.nodes.indigo.Qcg.Job":
                    deployment_type = "QCG"
                    break
    return deployment_type


def getslapolicy(template):
    sla_id = ''
    if 'policies' in template:
        for policy in template['policies']:
            if sla_id == '':
                for (k, v) in policy.items():
                    if "type" in v \
                            and (v['type'] == 'tosca.policies.indigo.SlaPlacement'
                                 or v['type'] == 'tosca.policies.Placement'):
                        if 'properties' in v:
                            sla_id = v['properties']['sla_id'] if 'sla_id' in v['properties'] \
                                else ''
                        break
    return sla_id


def eleasticdeployment(template):
    return hasnodeoftype(template, 'tosca.nodes.indigo.ElasticCluster')


def updatabledeployment(template):
    return hasnodeoftype(template, 'tosca.nodes.indigo.LRMS.WorkerNode')


def hasnodeoftype(template, nodetype):
    found = False
    if 'topology_template' in template:
        if 'node_templates' in template['topology_template']:
            for (j, u) in template['topology_template']['node_templates'].items():
                if found:
                    break
                for (k, v) in u.items():
                    if k == 'type' and nodetype in v:
                        found = True
                        break
    return found
