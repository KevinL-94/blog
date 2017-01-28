# auth\forms.py
from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(Form):      # 用户登录表单
    email = StringField('Email', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')     # BooleanField类表示复选框
    submit = SubmitField('Log In')



class RegistrationForm(Form):       # 用户注册表单
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    username = StringField('Username', validators=[Required(), Length(1,64), 
                                        Regexp('^[A-Za-z][A-Za-z0-9_,]*$', 0,   # Regexp:正则表达式
                                                'Username must have only letters, '
                                                'numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required(), 
                                            EqualTo('password2', message='Passwords must match.')])
    password2 = PasswordField('Comfirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):    # 验证表单中的email是否已存在
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self, field):    # 验证表单中的username是否已存在
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use.')


class ChangePasswordForm(Form):
    old_password = PasswordField('Old Password', validators=[Required()])
    password = PasswordField('New Password', validators=[Required(),
                                                EqualTo('password2', message='Password must match!')])
    password2 = PasswordField('Confirm New Password', validators=[Required()])
    submit = SubmitField('Update My Password')


class PasswordResetRequestForm(Form):
    email = StringField('Your Email', validators=[Required(), Length(1, 64), Email()])
    submit = SubmitField('Reset Password')


class PasswordResetForm(Form):
    email = StringField('Your Email', validators=[Required(), Length(1, 64), Email()])
    password = PasswordField('New Password', validators=[Required(),
                                                EqualTo('password2', message='Password must match!')])
    password2 = PasswordField('Confirm New Password', validators=[Required()])
    submit = SubmitField('Reset Password')


class ChangeEmailAddressForm(Form):
    email = StringField('New Email', validators=[Required(), Length(1, 64), Email()])
    password = StringField('Password', validators=[Required()])
    submit = SubmitField('Update Email Address')

    def validate_email(self, field):
        if User.query.filter_by(email=field.date).first():
            raise ValidationError('This email already registered!')