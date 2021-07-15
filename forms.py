from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, RadioField
from wtforms.fields.simple import HiddenField
from wtforms.validators import DataRequired, Email, EqualTo
from wtforms.fields.html5 import EmailField


class LoginForm(FlaskForm):
    email = EmailField('Email', [DataRequired(), Email()])
    password = PasswordField('Password', [DataRequired()])


class EditUserForm(FlaskForm):
    email = EmailField('Email *', [DataRequired(), Email()])
    name = StringField('Name *', [DataRequired()])
    apartment_number = StringField('Apartment Number *', [DataRequired()])
    role = RadioField('Role', choices=[
        # Value, Label
        ('Administrator', 'Administrator'),
        ('Guard', 'Guard'),
        ('Apartment Owner', 'Apartment Owner'),
    ], default='Administrator')


class CreateUserForm(FlaskForm):
    email = EmailField('Email *', [DataRequired(), Email()])
    password = PasswordField('Password *', [DataRequired(), EqualTo('password_confirmation', message='Password must match')])
    password_confirmation = PasswordField('Confirm Password *', [DataRequired()])
    name = StringField('Name *', [DataRequired()])
    apartment_number = StringField('Apartment Number *', [DataRequired()])
    role = RadioField('Role', choices=[
        # Value, Label
        ('Administrator', 'Administrator'),
        ('Guard', 'Guard'),
        ('Apartment Owner', 'Apartment Owner'),
    ], default='Administrator')


class RegisterVisitorForm(FlaskForm):
    guest_name = StringField("Guest's Name *", [DataRequired()])
    guest_email = EmailField("Guest's Email *", [DataRequired(), Email()])
    guest_id = StringField("Guest's ID *", [DataRequired()])
    guest_car_no = StringField("Guest's Car Number *", [DataRequired()])
    no_of_guests = IntegerField("No of Guests *", [DataRequired()])
    current_user_id = HiddenField("Current User ID", [DataRequired()])
