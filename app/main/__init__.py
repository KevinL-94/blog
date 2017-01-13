# main\__init__.py
from flask import Blueprint

main = Blueprint('main', __name__)  # 实例化蓝图

from . import views, errors