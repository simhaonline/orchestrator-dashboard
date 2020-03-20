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