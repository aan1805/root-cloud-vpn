from flask import Blueprint

bp = Blueprint('haproxy', __name__, url_prefix='/haproxy')

from app.haproxy import routes