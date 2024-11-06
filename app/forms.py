from flask import Flask, render_template, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField, StringField, PasswordField, TextAreaField
from werkzeug.utils import secure_filename
from wtforms.validators import InputRequired, DataRequired, Optional, Email, Length
import os

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Submit")
    
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Submit")
    
class UploadGPSForm(FlaskForm):
    file = FileField("File")
    submit = SubmitField("Upload GPX File")

class addFriendForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField("Submit")