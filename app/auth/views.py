# auth/views.py
from flask import render_template, redirect, request, url_for, flash
from flask.ext.login import login_required, login_user, logout_user, current_user
from . import auth
from .forms import LoginForm, RegistrationForm, ChangePasswordForm, ChangeEmailAddressForm, \
    PasswordResetRequestForm, PasswordResetForm
from .. import db
from ..models import User
from ..email import send_email


@auth.route('/login', methods = ['GET', 'POST'])    # 登入路由
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)    # 调用Flask-Login中的login_user()函数，把用户标记为已登录
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')    # 登出路由
@login_required     # 保护路由：只让认证用户访问该路由
def  logout():
    logout_user()    # 调用Flask-Login中的logout_user()函数，删除并重设用户会话
    flash('You have been logged out.')
    return redirect(url_for('main.index'))


@auth.route('/register', methods = ['GET', 'POST'])    # 用户注册路由
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, 
                    username=form.username.data, 
                    password=form.password.data)
        db.session.add(user)
        db.session.commit()
        token = user.generate_confirmation_token()      # 生成确认令牌
        send_email(user.email, 'Confirm Your Account',
                'auth/email/confirm', user=user, token=token)
        flash('A confirmation email has been sent to you by email')
        return redirect(url_for('main.index'))
    return render_template('auth/register.html', form=form)


@auth.route('/confirm/<token>')    #确认用户的账户
@login_required     # 保护路由：只让认证用户访问该路由
def confirm(token):
    if current_user.confirmed:    # 已确认用户重定向至首页
        return redirect(url_for('main.index'))
    if current_user.confirm(token):
        flash('You have confirmed your account. Thanks!')
    else:
        flash('The confirmation link is invalid or has expired.')
    return redirect(url_for('main.index'))


@auth.before_app_request
def before_request():
    if current_user.is_authenticated:
        current_user.ping()
        if not current_user.confirmed \
                and request.endpoint[:5] != 'auth.':
            return redirect(url_for('auth.unconfirmed'))


@auth.route('/unconfirmed')
def unconfirmed():
    if current_user.is_anonymous or current_user.confirmed:
        return redirect(url_for('main.index'))
    return render_template('auth/unconfirmed.html')


@auth.route('/confirm')
@login_required
def resend_confirmation():
    token = current_user.generate_confirmation_token()
    send_email(current_user, 'Confirm Your Account',    # 为current_user重新发送账户确认邮件
                'auth/email/confirm', user=current_user, token=token)
    flash('A new confirmation email has been sent to you by email.')
    return redirect(url_for('main.index'))


@auth.route('/change-password', methods=['GET', 'POST'])    # 修改密码
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.old_password.data):
            current_user.password = form.password.data
            db.session.add(current_user)
            flash('Your password has been updated!')
            return redirect(url_for('main.index'))
        else:
            flash('Invalid password!')
    return render_template('auth/change_password.html', form=form)


@auth.route('/reset', methods=['GET', 'POST'])    # 重置密码请求
def password_reset_request():
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token()
            send_email(user.mail, "Reset Your Password",
                        'auth/email/reset_password',
                        user=user, token=token,
                        next=request.args.get('next'))
            flash('An email with instructions to reset your password has been '     ###
                  'sent to you.')
        return redirect(url_for('auth.login'))
    return render_template('auth/reset_password.html', form=form)


@auth.route('/reset/<token>', methods=['GET', 'POST'])    # 重置密码
def password_reset(token):
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(form.email.data).first()
        if user is None:                                        ###
            return redirect(url_for('main.index'))
        if user.reset_password(token, form.password.data):
            flash('Your password has been updated.')
            return redirect(url_for('auth.login'))
        else:
            return redirect(url_for('main.index'))
    return render_template('auth/password_reset.html', form=form)


@auth.route('/change-email', methods=['GET', 'POST'])    # 修改邮箱请求
@login_required
def change_email_request():
    form = ChangeEmailAddressForm()
    if form.validate_on_submit():
        if current_user.verify_password(form.password.data):
            new_email = form.email.data
            token = current_user.generate_change_email_token(new_email)
            send_email(new_email, 'Confirm your new email address', 'auth/email/change_email',
                       user=current_user, token=token)
            return redirect(url_for('main.index'))
        else:
            flash('Invalid email or password.')
    return render_template('auth/change_email.html', form=form)


@auth.route('/change-email/<token>')    # 修改邮箱
@login_required
def change_email(token):
    if current_user.change_email(token):
        flash('Your email address has been updated!')
    else:
        flash('Invalid request')
    return redirect(url_for('main.index'))