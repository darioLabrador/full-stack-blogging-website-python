from flask_wtf import RecaptchaField
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.fields.simple import EmailField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp

# Render user registration form
class RegistrationForm(FlaskForm):
    email = EmailField(validators=[DataRequired(), Regexp('^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
                                                          message="Enter a valid email address(@gmail.com, @outlook.com, etc.).")])
    firstname = StringField(validators=[DataRequired(), Regexp('^[a-zA-Z]+(-[a-zA-Z]+)*$', message="Enter valid firstname (only letters or symbol\'-\').")])
    lastname = StringField(validators=[DataRequired(), Regexp('^[a-zA-Z]+(-[a-zA-Z]+)*$', message="Enter valid lastname (only letters or symbol\'-\').")])
    phone = StringField(validators=[DataRequired(), Regexp('^02\d-\d{8}$|^011\d-\d{7}$|^01\d1-\d{7}$|^01\d{3}-\d{5,6}$',
                                                           message="Enter a valid UK landline phone number (Max. of 15 digits, and Area codes from 3 to 5 digits and include \'-\').")])

    password = PasswordField(validators=[DataRequired(), Length(6,15, '* Password must be between 8 and 15 characters in length'),
                                         Regexp('(?=.*[A-Z])', message='* Password must contain at least one upper case letter!'),
                                         Regexp('(?=.*[a-z])', message='* Password must contain at least one lower case letter!'),
                                         Regexp('.*\d', message='* Password must contain at least a digit!'),
                                         Regexp('(.*\W)|(?=.*_)', message='* Password must contain at least one special character!'),
                                         ])
    confirm_password = PasswordField(validators=[DataRequired(), EqualTo('password', message='Both password fields must be equal!')])
    role = StringField(validators=[DataRequired()])
    submit = SubmitField()

# Render user login form
class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])
    pin = StringField(validators=[DataRequired()])
    recaptcha = RecaptchaField()
    submit = SubmitField()

