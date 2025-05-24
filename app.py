from config import app, login_manager, User
from flask import render_template, request
import re

# Define malicious patterns for SQL Injections, XXS, and pat traversal
WAF_RULES = {
    "sql_injection": re.compile(r"(?i)\b(union|select|insert|drop|alter)\b|;|`|'",re.IGNORECASE),
    "xss": re.compile(r"(?i)<script>|<iframe>|%3Cscript%3E|%3Ciframe%3E",re.IGNORECASE),
    "path_traversal": re.compile(r"(?i)\.\./|\.\.|%2e%2e%2f|%2e%2e/|\.\.%2f",re.IGNORECASE)
}

# Check for attack attempts
@app.before_request
def waf_protection():
    for attack_type, patterns in WAF_RULES.items():
        if patterns.search(request.path) or patterns.search(request.query_string.decode()):
            return render_template("errors/attack_attempt.html", attack_type=attack_type)

#Home
@app.route('/')
def index():
    return render_template('home/index.html')

# Load user by id
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'))