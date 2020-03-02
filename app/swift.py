import app
import hashlib
import os
import sys

from swiftclient import Connection


def getSwiftConnection():
    if app.app.config['SWIFT_AUTHVER'] == '3':
        os_options = {
            'project_name': app.app.config['SWIFT_TENANT'],
            'project_domain_name': '',
            'user_domain_name': '',
        }
        connection = Connection(
            auth_version='3',
            authurl=app.app.config['SWIFT_AUTHURL'],
            user=app.app.config['SWIFT_USER'],
            key=app.app.config['SWIFT_KEY'],
            os_options=os_options)

    elif app.app.config['SWIFT_AUTHVER'] == '1':
        connection = Connection(
            auth_version='1',
            authurl=app.app.config['SWIFT_AUTHURL'],
            user=app.app.config['SWIFT_USER'],
            key=app.app.config['SWIFT_KEY'],
            tenant_name='UNUSED')

    else:
        raise NotImplementedError(
            'auth_version? {!r}'.format(app.app.config['SWIFT_AUTHVER']))

    return connection


