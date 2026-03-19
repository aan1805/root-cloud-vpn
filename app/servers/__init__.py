from flask import Blueprint

bp = Blueprint('servers', __name__, url_prefix='/servers')

from app.servers import routes