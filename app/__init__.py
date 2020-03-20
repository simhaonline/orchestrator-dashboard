import sys
import socket

from flask import Flask
from flask_alembic import Alembic
from sqlalchemy_utils import database_exists, create_database
from sqlalchemy import Table, Column, String, MetaData
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_dance.consumer import OAuth2ConsumerBlueprint
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, upgrade
from app.extensions.flask_tosca import ToscaInfo
from app.extensions.flask_vault import Vault

import logging

# db variable initialization
db: SQLAlchemy = SQLAlchemy()

# initialize Migrate
migrate: Migrate = Migrate()

# Intialize the extension
alembic: Alembic = Alembic()

# initialize ToscaInfo extension
tosca : ToscaInfo = ToscaInfo()

# initialize Vault extension
vault : Vault = Vault()

app = Flask(__name__, instance_relative_config=True)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = "30bb7cf2-1fef-4d26-83f0-8096b6dcc7a3"
app.config.from_object('config.default')
app.config.from_json('config.json')
app.config.from_json('vault-config.json')

profile = app.config.get('CONFIGURATION_PROFILE')
if profile != 'default':
    app.config.from_object('config.' + profile)

@app.context_processor
def inject_settings():
    return dict(
        footer_template=app.config.get('FOOTER_TEMPLATE'),
        welcome_message=app.config.get('WELCOME_MESSAGE'),
        navbar_brand_text=app.config.get('NAVBAR_BRAND_TEXT'),
        enable_vault_integration=False if app.config.get('ENABLE_VAULT_INTEGRATION').lower() == 'no' else True,
        external_links=app.config.get('EXTERNAL_LINKS') if app.config.get('EXTERNAL_LINKS') else [],
        enable_advanced_menu=app.config.get('FEATURE_ADVANCED_MENU') if app.config.get('FEATURE_ADVANCED_MENU') else "no",
        enable_update_deployment=app.config.get('FEATURE_UPDATE_DEPLOYMENT') if app.config.get(
                                   'FEATURE_UPDATE_DEPLOYMENT') else "no",
        hidden_deployment_columns=app.config.get('FEATURE_HIDDEN_DEPLOYMENT_COLUMNS') if app.config.get(
                                    'FEATURE_HIDDEN_DEPLOYMENT_COLUMNS') else ""
    )


db.init_app(app)
migrate.init_app(app, db)
alembic.init_app(app, run_mkdir=False)
tosca.init_app(app)

if app.config.get("ENABLE_VAULT_INTEGRATION"):
    vault.init_app(app)

from app.errors.handlers import errors_bp
app.register_blueprint(errors_bp)

iam_base_url = app.config['IAM_BASE_URL']
iam_token_url = iam_base_url + '/token'
iam_refresh_url = iam_base_url + '/token'
iam_authorization_url = iam_base_url + '/authorize'

iam_blueprint = OAuth2ConsumerBlueprint(
    "iam", __name__,
    client_id=app.config['IAM_CLIENT_ID'],
    client_secret=app.config['IAM_CLIENT_SECRET'],
    base_url=iam_base_url,
    token_url=iam_token_url,
    auto_refresh_url=iam_refresh_url,
    authorization_url=iam_authorization_url,
    redirect_to='home'
)
app.register_blueprint(iam_blueprint, url_prefix="/login")

from app.users.users import users_bp
app.register_blueprint(users_bp, url_prefix="/users")

from app.deployments.deployments import deployments_bp
app.register_blueprint(deployments_bp, url_prefix="/deployments" )

from app.providers.providers import providers_bp
app.register_blueprint(providers_bp, url_prefix="/providers")

if app.config.get("ENABLE_VAULT_INTEGRATION"):
    from app.vault.vault import vault_bp
    app.register_blueprint(vault_bp, url_prefix="/vault")

mail = Mail(app)

# logging

loglevel = app.config.get("LOG_LEVEL") if app.config.get("LOG_LEVEL") else "INFO"

numeric_level = getattr(logging, loglevel.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % loglevel)

logging.basicConfig(level=numeric_level)

from app import routes

# check if database exists
engine = db.get_engine(app)
if not database_exists(engine.url):  # Checks for the first time
    create_database(engine.url)  # Create new DB
    if database_exists(engine.url):
        app.logger.debug("New database created")
    else:
        app.logger.debug("Cannot create database")
        sys.exit()
else:
    # for compatibility with old non-orm version
    # check if existing db is not versioned
    if not engine.dialect.has_table(engine.connect(), "alembic_version"):
        # create versioning table and assign initial release
        baseversion = app.config['SQLALCHEMY_VERSION_HEAD']
        meta = MetaData()
        alembic_version = Table(
            'alembic_version',
            meta,
            Column('version_num', String(32), primary_key=True),
        )
        meta.create_all(engine)
        ins = alembic_version.insert().values(version_num=baseversion)
        conn = engine.connect()
        result = conn.execute(ins)


# update database, run flask_migrate.upgrade()
with app.app_context():
    upgrade()

# IP of server
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    # doesn't even have to be reachable
    s.connect(('10.255.255.255', 1))
    app.ip = s.getsockname()[0]
except:
    app.ip = '127.0.0.1'
finally:
    s.close()

if __name__ == "__main__":
    app.run(host='0.0.0.0')
