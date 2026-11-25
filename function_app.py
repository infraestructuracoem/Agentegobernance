import azure.functions as func
from blueprints.evaluate_prompt import bp_evaluate
from blueprints.create_agent import bp_create
from blueprints.audit_endpoint import bp_audit
from blueprints.execute_remediation import bp_remediation
from blueprints.send_notification import bp_notification

app = func.FunctionApp()

app.register_blueprint(bp_evaluate)
app.register_blueprint(bp_create)
app.register_blueprint(bp_audit)
app.register_blueprint(bp_remediation)
app.register_blueprint(bp_notification)
