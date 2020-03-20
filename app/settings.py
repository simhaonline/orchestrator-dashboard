from app import app

toscaDir = app.config['TOSCA_TEMPLATES_DIR'] + "/"
toscaParamsDir = app.config.get('TOSCA_PARAMETERS_DIR')
toscaMetadataDir = app.config.get('TOSCA_METADATA_DIR')

iamUrl = app.config['IAM_BASE_URL']
iamClientID = app.config.get('IAM_CLIENT_ID')
iamClientSecret = app.config.get('IAM_CLIENT_SECRET')
iamGroups = app.config.get('IAM_GROUP_MEMBERSHIP')

tempSlamUrl = app.config.get('SLAM_URL') if app.config.get('SLAM_URL') else "" 

orchestratorUrl = app.config['ORCHESTRATOR_URL']
orchestratorConf = {
  'cmdb_url': app.config.get('CMDB_URL'),
  'slam_url': tempSlamUrl + "/rest/slam",
  'im_url': app.config.get('IM_URL'),
  'monitoring_url': app.config.get('MONITORING_URL'),
  'vault_url' : app.config.get('VAULT_URL')
}

