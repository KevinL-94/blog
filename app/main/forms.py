# main\forms.py
# -*- coding: utf-8 -*-
from flask.ext.wtf import Form
from flask_pagedown.fields import PageDownField
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, SelectField, \
    ValidationError
from wtforms.validators import Required, Length, Email, Regexp
from ..models import Role, User


class NameForm(Form):   # 定义表单类
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('提交')

class EditProfileForm(Form):
    name = StringField('真实姓名', validators=[Length(0, 64)])
    location = StringField('地址', validators=[Length(0, 64)])
    about_me = TextAreaField('关于我')
    submit = SubmitField('提交')

class AdminEditProfileForm(Form):
    email = StringField('邮箱地址', validators=[Required(), Length(1, 64), Email()])
    username = StringField('用户名', validators=[Required(), Length(1, 64),
                                        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 
                                            'Usernames must have only letters, '
                                            'numbers, dots or underscores')])
    confirmed = BooleanField('已验证')
    role = SelectField('角色', coerce=int)
    name = StringField('真实姓名', validators=[Length(0, 64)])
    location = StringField('地址', validators=[Length(0, 64)])
    about_me = TextAreaField('关于我')
    submit = SubmitField('提交')

    def __init__(self, user, *args, **kwargs):
        super(AdminEditProfileForm, self).__init__(*args, **kwargs)
        self.role.choices = [(role.id, role.name)
                            for role in Role.query.order_by(Role.name).all()]
        self.user = user

    def validate_email(self, field):    # 下划线后的内容对应表单的名字，即：field.data == form.email.data
        if field.data != self.user.email and \
            User.query.filter_by(email=field.data).first():
            raise ValidationError('该邮箱地址已存在')

    def validate_username(self, field):
        if field.data != self.user.username and \
            User.query.filter_by(username=field.data).first():
            raise ValidationError('该用户名已存在')


class PostForm(Form):
    body = PageDownField("What's on your mind?", validators=[Required()])
    submit = SubmitField('提交')


class CommentForm(Form):
    body = StringField('', validators=[Required()])
    submit = SubmitField('提交')