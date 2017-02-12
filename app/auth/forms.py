# auth\forms.py
# -*- coding: utf-8 -*-
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(Form):      # 用户登录表单
    email = StringField('邮箱', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('密码', validators=[Required()])
    remember_me = BooleanField('记住我')     # BooleanField类表示复选框
    submit = SubmitField('登陆')



class RegistrationForm(Form):       # 用户注册表单
    email = StringField('邮箱', validators=[Required(), Length(1,64), Email()])
    username = StringField('用户名', validators=[Required(), Length(1,64), 
                                        Regexp('^[A-Za-z][A-Za-z0-9_,]*$', 0,   # Regexp:正则表达式
                                                'Username must have only letters, '
                                                'numbers, dots or underscores')])
    password = PasswordField('密码', validators=[Required(), 
                                            EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('确认密码', validators=[Required()])
    submit = SubmitField('注册')

    def validate_email(self, field):    # 验证表单中的email是否已存在
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('该邮箱已注册')

    def validate_username(self, field):    # 验证表单中的username是否已存在
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('该用户名已存在')


class ChangePasswordForm(Form):
    old_password = PasswordField('旧密码', validators=[Required()])
    password = PasswordField('新密码', validators=[Required(),
                                                EqualTo('password2', message='两次输入密码需一致！')])
    password2 = PasswordField('确认新密码', validators=[Required()])
    submit = SubmitField('更新密码')


class PasswordResetRequestForm(Form):
    email = StringField('邮箱地址', validators=[Required(), Length(1, 64), Email()])
    submit = SubmitField('重置密码')


class PasswordResetForm(Form):
    email = StringField('邮箱地址', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('新密码', validators=[Required(),
                                                EqualTo('password2', message='两次输入密码需一致！')])
    password2 = PasswordField('确认新密码', validators=[Required()])
    submit = SubmitField('重置密码')


class ChangeEmailAddressForm(Form):
    email = StringField('新邮箱地址', validators=[Required(), Length(1, 64), Email()])
    password = StringField('密码', validators=[Required()])
    submit = SubmitField('更新邮箱地址')

    def validate_email(self, field):
        if User.query.filter_by(email=field.date).first():
            raise ValidationError('该邮箱已注册！')