from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Email


class LoginForm(FlaskForm):
    login = StringField("login: ", validators=[DataRequired()])
    password = StringField("password: ", validators=[DataRequired()])
    submit = SubmitField("Login")


class CreateUserForm(FlaskForm):
    login = StringField("login: ", validators=[DataRequired()])
    password = StringField("password: ", validators=[DataRequired()])
    email = StringField("email: ", validators=[Email()])
    submit = SubmitField("ADD")


class CreateServiceForm(FlaskForm):
    service = StringField("service: ", validators=[DataRequired()])
    password = StringField("password: ", validators=[DataRequired()])
    master_password = StringField("mater_password: ", validators=[DataRequired()])
    submit = SubmitField()


class DecodePassword(FlaskForm):
    service = StringField("service: ", validators=[DataRequired()])
    master_password = StringField("mater_password: ", validators=[DataRequired()])
    submit = SubmitField()