# main\forms.py
from flask.ext.wtf import Form
from wtforms import StringField, SubmitField
from wtforms.validators import Required

class NameForm(Form):   # 定义表单类
    name = StringField('What is your name?', validators=[Required()])
    submit = SubmitField('Submit')