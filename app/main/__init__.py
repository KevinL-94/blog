# main\__init__.py
# -*- coding: utf-8 -*-
from flask import Blueprint

main = Blueprint('main', __name__)  # 实例化蓝图,参数一为蓝图名

from . import views, errors
from ..models import Permission

@main.app_context_processor
def inject_permissions():
    return dict(Permission=Permission)