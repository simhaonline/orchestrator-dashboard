import requests, json
from flask import session


def get_sla_extra_info(access_token, service_id, cmdb_url):
    headers = {'Authorization': 'bearer %s' % (access_token)}
    url = cmdb_url + "/service/id/" + service_id
    response = requests.get(url, headers=headers, timeout=20)
    response.raise_for_status()

    service_type=response.json()['data']['service_type']
    sitename=response.json()['data']['sitename']
    endpoint=response.json()['data'].get('endpoint')
    iam_enabled=response.json()['data'].get('iam_enabled')
    if 'properties' in response.json()['data']:
        if 'gpu_support' in response.json()['data']['properties']:
            service_type = service_type + " (gpu_support: " + str(response.json()['data']['properties']['gpu_support']) + ")"

    return sitename, endpoint, service_type, iam_enabled

def get_slas(access_token, slam_url, cmdb_url):

    headers = {'Authorization': 'bearer %s' % (access_token)}

    url = slam_url + "/preferences/" + session['organisation_name']
    
    response = requests.get(url, headers=headers, timeout=20, verify=False)

    response.raise_for_status()
    slas = response.json()['sla']

    for i in range(len(slas)):
       sitename, endpoint, service_type, iam_enabled = get_sla_extra_info(access_token,slas[i]['services'][0]['service_id'], cmdb_url)
       slas[i]['service_id']=slas[i]['services'][0]['service_id']
       slas[i]['service_type']=service_type
       slas[i]['sitename']=sitename
       slas[i]['endpoint']=endpoint
       slas[i]['iam_enabled']=iam_enabled

    return slas
