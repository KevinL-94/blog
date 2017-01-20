# app\__init__.py
from flask import Flask
from flask.ext.bootstrap import Bootstrap
from flask.ext.moment import Moment
from flask.ext.mail import Mail
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager
from flask_pagedown import PageDown
from config import config


bootstrap = Bootstrap()      # 初始化Flask-Bootstrap
moment = Moment()        # 初始化Flask-Moment
db = SQLAlchemy()    # 表示程序使用的数据库
mail = Mail()
pagedown = PageDown()

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'

def create_app(config_name):    # 工厂函数
    app = Flask(__name__)   # Flask初始化
    app.config.from_object(config[config_name]) # 获得配置
    config[config_name].init_app(app)

    bootstrap.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    pagedown.init_app(app)

    # 附加路由和自定义的错误页面

    from .main import main as main_blueprint    # 将蓝图注册到工厂函数中
    app.register_blueprint(main_blueprint)

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix = '/auth')

    return app
