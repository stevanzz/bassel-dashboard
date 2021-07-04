from typing import Optional
from flask import Flask, request, render_template, redirect, jsonify, make_response
from flask_restful import Api
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
import config
import jwt as jwt_lib


app = Flask(__name__, static_url_path="", static_folder="static")

# Set your Desired Application Settings
app.config.from_object(config.DevelopmentConfig())

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize SMTP
mail = Mail(app)

import resources

# Initialize API resources
api = Api(app)

# Frontend resources
api.add_resource(resources.Login, '/login')
api.add_resource(resources.Logout, '/logout')
api.add_resource(resources.VisitorRecords, '/visitor-records')
api.add_resource(resources.Users, '/users')
api.add_resource(resources.RegisterVisitorPage, '/register-visitor')

# Backend resources
api.add_resource(resources.UserDatatables, '/api/users')
api.add_resource(resources.User, '/api/user', '/api/user/<user_id>')
api.add_resource(resources.VisitorRecordsDatatables, '/api/visitor-records')
api.add_resource(resources.RegisterVisitor, '/api/register-visitor')

api.add_resource(resources.Index, '/')

# JWT configuration
jwt = JWTManager(app)

# Register a callback function that takes whatever object is passed in as the
# identity when creating JWTs and converts it to a JSON serializable format.
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.to_dict()



