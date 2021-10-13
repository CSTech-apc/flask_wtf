from app import app, db, bcrypt, mail
from flask import render_template, url_for, redirect, flash
from app.forms import RegistrationForm, LoginForm, ResetRequestForm, ResetPasswordForm
from app.models import User
from flask_login import login_user, logout_user, current_user, login_required
from flask_mail import Message


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/account")
@login_required
def account():
    return render_template("account.html")


@app.route("/register", methods=["POST", "GET"])
@login_required
def register():
    # if current_user.is_authenticated:
    #     return redirect(url_for("account"))
    form = RegistrationForm()
    if form.validate_on_submit():
        encrypted_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=encrypted_password,
        )
        db.session.add(user)
        db.session.commit()
        flash(
            f"account created successfully for {form.username.data}", category="success"
        )
        return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["POST", "GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("account"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash(f"Login successful for {form.email.data}", category="success")
            return redirect(url_for("account"))
        else:
            flash(f"Login unsuccessful for {form.email.data}", category="danger")
            return redirect(url_for("login"))
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/list")
def list():
    users = User.query.all()
    return render_template("list.html", users=users)


def send_mail(user):
    token = user.get_token()
    msg = Message(
        "Password Reset Request", recipients=[user.email], sender="noreply@codejana.com"
    )
    msg.body = f"""To reset your password. Please follow the link below.    
    {url_for("reset_token", token=token, _external=True)}    
    If you didn't send a password reset request. Please ignore this message.
    """
    mail.send(msg)


@app.route("/reset_request", methods=["POST", "GET"])
def reset_request():
    form = ResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_mail(user)
            flash("Reset request sent. Check your mail.", "success")
            return redirect(url_for("login"))
    return render_template("reset_request.html", form=form)


@app.route("/reset_request/<token>", methods=["POST", "GET"])
def reset_token(token):
    user = User.verify_token(token)
    if user is None:
        flash("That is invalid token or expired. Please try again.", "warning")
        return redirect(url_for("reset_request"))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user.password = hashed_password
        db.session.commit()
        flash("Password changed! Please login!", "success")
        return redirect(url_for("login"))
    return render_template("change_password.html", form=form)
