from app import app
from flask import make_response

__version__ = '1.2.0'


@app.route('/info')
def info():
    info = { "name": "orchestrator-dashboard", "version": __version__ }
    resp = make_response(info)
    resp.status_code = 200
    resp.mimetype = 'application/json'
    return resp
