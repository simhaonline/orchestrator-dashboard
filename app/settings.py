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
  'monitoring_url': app.config.get('MONITORING_URL')
}

external_links = app.config.get('EXTERNAL_LINKS') if app.config.get('EXTERNAL_LINKS') else []
enable_advanced_menu = app.config.get('FEATURE_ADVANCED_MENU') if app.config.get('FEATURE_ADVANCED_MENU') else "no"
enable_update_deployment = app.config.get('FEATURE_UPDATE_DEPLOYMENT') if app.config.get('FEATURE_UPDATE_DEPLOYMENT') else "no"
hidden_deployment_columns = app.config.get('FEATURE_HIDDEN_DEPLOYMENT_COLUMNS') if app.config.get('FEATURE_HIDDEN_DEPLOYMENT_COLUMNS') else ""
