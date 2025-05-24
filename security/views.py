from flask import Blueprint, render_template
from flask_login import login_required
from config import roles_required, Log, User

security_bp = Blueprint('security', __name__, template_folder='templates')

# Display logs
@security_bp.route('/security')
@roles_required('sec_admin')
@login_required
def security():
    logs = Log.query.join(User).all()

    # Open and read security.log
    with open('security.log', 'r') as f:
        log_lines = f.readlines()[-10:]

    return render_template('security/security.html', logs=logs, log_lines=log_lines)
