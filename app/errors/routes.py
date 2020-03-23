from flask import render_template, request, Blueprint
from app import app

errors_bp = Blueprint('errors', __name__,
                           template_folder='templates',
                           static_folder='static'
                           )


@errors_bp.app_errorhandler(403)
def forbidden(error):
    return render_template('403.html', message=error.description)


@errors_bp.app_errorhandler(404)
def page_not_found(error):
    app.logger.error('Page not found: %s', request.path)
    return render_template('404.html'), 404


@errors_bp.app_errorhandler(500)
def internal_server_error(error):
    app.logger.error('Server Error: %s', error)
    return render_template('500.html', support_email=app.config.get('SUPPORT_EMAIL')), 500
