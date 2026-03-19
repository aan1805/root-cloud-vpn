from flask import Blueprint

bp = Blueprint('protocols', __name__, url_prefix='/servers/<int:server_id>/protocols')

from app.protocols import routes