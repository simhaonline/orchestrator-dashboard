import json
from flask import Blueprint, render_template, request, flash
from app.lib import auth
from .swift import Swift
import logging


swift_bp = Blueprint('swift_bp', __name__, template_folder='templates', static_folder='static')


@swift_bp.route('/createswifttoken', methods=['GET', 'POST'])
@auth.authorized_with_valid_token
@auth.only_for_admin
def createswifttoken():
    if request.method == 'POST':
        logging.debug("Form data: " + json.dumps(request.form.to_dict()))
        form_data = request.form.to_dict()
        swift_a = form_data["swiftauthurl"] if "swiftauthurl" in form_data else None
        swift_v = form_data["swiftauthversion"] if "swiftauthversion" in form_data else None
        swift_u = form_data["swiftuser"] if "swiftuser" in form_data else None
        swift_k = form_data["swiftkey"] if "swiftkey" in form_data else None
        swift_t = form_data["swifttenant"] if "swifttenant" in form_data else None
        swift_b = form_data["swifcontainer"] if "swifcontainer" in form_data else None

        if swift_a and swift_v and swift_u and swift_k and swift_t and swift_b:
            swift = Swift()
            t = "OS" + "§" \
                + swift_a + "§" \
                + swift_v + "§" \
                + swift_u + "§" \
                + swift_k + "§" \
                + swift_t + "§" \
                + swift_b
            token = swift.pack(t)
            return render_template('createswifttoken.html', token=token)
        else:
            flash("All fields must be filled! Cannot create swift token.")
    return render_template('createswifttoken.html')
