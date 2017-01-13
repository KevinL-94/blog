# app\models.py
from flask import current_app
from flask.ext.login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash   # 计算密码哈希值并核对
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer   # 生成确认令牌
from . import db
from . import login_manager

class Role(db.Model):   # 定义数据库模型：roles表
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    users = db.relationship('User', backref='role', lazy='dynamic')

    def __repr__(self):
        return '<Role %r>' % self.name


class User(UserMixin, db.Model):   # 定义数据库模型：users表，继承自UserMixin，db.Model
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(64), unique=True, index=True)
    confirmed = db.Column(db.Boolean, default=False)

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
        if data.get('change_email') != sekf.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email) is not None:
            return False
        self.email = new_email
        db.session.add(self)
        return True


    def __repr__(self):
        return '<User %r>' % self.username

@login_manager.user_loader    # 加载用户的回调函数
def load_user(user_id):
    return User.query.get(int(user_id))
