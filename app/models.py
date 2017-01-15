# app\models.py
# -*- coding: UTF-8 -*-
from flask import current_app
from flask.ext.login import UserMixin, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash   # 计算密码哈希值并核对
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer   # 生成确认令牌
from . import db, login_manager


class Permission:
    FOLLOW = 0x01    # 0x:十六进制
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class Role(db.Model):   # 定义数据库模型：roles表
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |    # |表示逻辑位或
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):    # 返回一个具有可读性的字符串表示该模型，可在调试和测试时使用
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):   # 定义数据库模型：users表，继承自UserMixin，db.Model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(64), unique=True, index=True)
    confirmed = db.Column(db.Boolean, default=False)

    def __init__(self, **kwargs):    # 定义默认角色
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    @property   # @property装饰器，把password方法变成属性调用
    def password(self):
        raise AttributeError('password is not a readable attribute')    # self.password为只写属性，不可读

    @password.setter    # @password.setter装饰器，把方法变成属性赋值
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):     # 生成确认令牌
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})    # dumps()为指定数据生成加密签名，再序列化生成令牌字符串

    def confirm(self, token):    # 检验令牌，及令牌中的id是否与current_user中的id匹配
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)   # load()解码令牌，检验签名和过期时间
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password
        db.session.add(self)
        return True

    def change_email_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self, token, new_email):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email) is not None:
            return False
        self.email = new_email
        db.session.add(self)
        return True

    def can(self, permissions):    # 检查用户是否有指定权限
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions    # 当前用户的权限与指定权限逻辑与操作

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)


    def __repr__(self):
        return '<User %r>' % self.username

class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser

@login_manager.user_loader    # 加载用户的回调函数
def load_user(user_id):
    return User.query.get(int(user_id))
