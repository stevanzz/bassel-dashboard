from flask import render_template, make_response, redirect, jsonify, request, jsonify, url_for
from flask_restful import Resource
from flask_jwt_extended import create_access_token
from flask_login import login_required, login_user, logout_user, current_user
from flask_mail import Message
from flask_wtf.csrf import CSRFError
import models
from functools import wraps
from app import app, db, mail, login_manager
import jwt as jwt_lib
import json
import datetime
import base64
import qrcode
from utils import is_safe_url, Admin, Guard, Apartment_Owner
from forms import LoginForm, EditUserForm, CreateUserForm, RegisterVisitorForm


# Custom decorator to validate JWT
# flask_jwt_extended.set_access_cookies is not working properly
def login_required_jwt():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            access_token = request.cookies.get('access_token')
            try:
                if not access_token:
                    raise APIError(401, 'JWT not found')

                jwt_lib.decode(
                    access_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            except Exception as e:
                return redirect(url_for('login'))

            return fn(*args, **kwargs)

        return decorator

    return wrapper


# Custom decorator to restrict user access
def user_access_control(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            if current_user.role not in roles:
                return make_response(jsonify(response="Your account doesn't have access to this page"), 403)

            return fn(*args, **kwargs)

        return decorator

    return wrapper


# Inject current_user object to all templates
# This is to control sidebar menu based on user access
# @app.context_processor
def inject_dict_for_all_templates():
    access_token = request.cookies.get('access_token')
    try:
        if access_token:
            data = jwt_lib.decode(
                access_token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
            return dict(current_user=data['sub'])
        else:
            return dict()
    except Exception as e:
        return dict()


# ------------- FRONTEND -------------
class Login(Resource):
    def get(self):
        if current_user.is_authenticated:
            return redirect(url_for(self.get_default_page(current_user)))

        form = LoginForm()
        return make_response(render_template('home.html', form=form), 200)

    def post(self):
        form = LoginForm()
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data

            user = models.User.query.filter_by(email=email).one_or_none()
            if user is None:
                raise APIError(404, 'Email is not exist')
            elif not user.check_password(password):
                raise APIError(401, 'Wrong email or password')
            else:
                # JWT create access token
                # access_token = create_access_token(identity=user)
                # return {'access_token': access_token}

                login_user(user)
                next = request.args.get('next')
                if next:
                    if not is_safe_url(next):
                        raise APIError(400, 'Bad Request')

                    return jsonify(redirect=next)

                default_redirect_url = self.get_default_page(user)

                if default_redirect_url is None:
                    raise APIError(400, 'Bad Request')

                return jsonify(redirect=default_redirect_url)
        else:
            raise APIError(400, "Form is not valid")

    def get_default_page(self, user):
        if user.role == 'administrator':
            return '/users'
        elif user.role == 'guard':
            return '/visitor-records'
        elif user.role == 'apartment_owner':
            return '/register-visitor'
        else:
            return None


class Logout(Resource):
    @login_required
    def get(self):
        # response = make_response(render_template('home.html'), 200)
        # response.delete_cookie('access_token')
        # return response
        logout_user()
        return redirect(url_for('login'))


class VisitorRecords(Resource):
    @login_required
    @user_access_control(Admin, Guard)
    def get(self):
        return make_response(render_template('admin/visitor_records.html'), 200)


class Users(Resource):
    @login_required
    @user_access_control(Admin)
    def get(self):
        edit_form = EditUserForm()
        create_form = CreateUserForm()
        return make_response(
            render_template(
                'admin/user_list.html',
                edit_form=edit_form,
                create_form=create_form,
            ),
            200)


class RegisterVisitorPage(Resource):
    @login_required
    @user_access_control(Admin, Apartment_Owner)
    def get(self):
        form = RegisterVisitorForm()
        form.current_user_id.data = current_user.id
        return make_response(render_template('admin/register_visitor.html', form=form), 200)


class QRcodeViewer(Resource):
    @login_required
    @user_access_control(Admin, Guard)
    def get(self, QR_code):
        try:
            base64_bytes = QR_code.encode('ascii')
            message_bytes = base64.b64decode(base64_bytes)
            message = json.loads(message_bytes.decode('ascii'))
            record_id = message.get('record_id')
             # Check QR code exist
            record = models.VisitorRecords.query.filter_by(id=record_id).first()
            if not record:
                raise APIError(400, 'Record is not found')

            user = models.User.query.filter_by(id=record.owner_id).first()
            data = {
                "ID": record.id,
                "apartment_number": user.apartment_number,
                "owner_email": user.email,
                "guest_name": record.guest_name,
                "guest_id": record.guest_id,
                "guest_car_number": record.guest_car_number,
            }
            return make_response(render_template('admin/qr_viewer.html', data=data), 200)
        except Exception as e:
            raise APIError(400, "QR Code is not valid")


class Index(Resource):
    @login_required
    def get(self):
        return redirect('/users')


# ------------- BACKEND -------------

class UserDatatables(Resource):
    @login_required
    def get(self):
        search = request.args.get('search[value]') or None
        start = int(request.args.get('start')) or 0
        length = int(request.args.get('length')) or 10
        action_button = '''
            <button type="button" rel="tooltip" class="btn btn-success edit">
                <i class="material-icons">edit</i>
                <div class="ripple-container"></div>
            </button>
            <button type="submit" rel="tooltip" class="btn btn-danger remove">
                <i class="material-icons">close</i>
                <div class="ripple-container"></div>
            </button>
            '''
        res = []
        total_records = db.session.query(models.User).count()
        if search:
            query = models.User.query.filter(
                models.User.email.contains(search)).order_by(models.User.id.asc())
        else:
            query = models.User.query.order_by(models.User.id.asc())

        filtered_records = query.all()

        if length:
            query = query.limit(length)
        if start:
            query = query.offset(start)

        for user in query:
            user_data = {
                "email": user.email,
                "name": user.name,
                "apartment_number": user.apartment_number,
                "role": user.role,
            }
            dt_data = {
                "DT_RowAttr": {
                    "data-id": user.id,
                    "data-user": json.dumps(user_data),
                },
            }
            res.append({**dt_data, **user_data, **{'action': action_button}})
        return jsonify({
            "recordsTotal": total_records,
            "recordsFiltered": len(filtered_records),
            'data': res
        })


class User(Resource):
    @login_required
    def post(self):
        form = CreateUserForm()
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            name = form.name.data
            apartment_number = form.apartment_number.data
            role = form.role.data

            # Check email exist
            is_exist = models.User.query.filter_by(email=email).first()
            if (is_exist):
                raise APIError(400, 'Email exists')

            new_user = models.User(
                email=email,
                password=password,
                name=name,
                apartment_number=apartment_number,
                role=role,
                created_date=datetime.datetime.now(),
                updated_date=datetime.datetime.now()
            )
            db.session.add(new_user)
            db.session.commit()
            res = {
                'id': new_user.id,
                'email': new_user.email,
                'name': new_user.name,
                'apartment_number': new_user.apartment_number,
                'role': new_user.role,
            }
            return res
        else:
            raise APIError(400, "Form is not valid")

    @login_required
    def put(self):
        form = EditUserForm()
        if form.validate_on_submit():
            email = form.email.data
            name = form.name.data
            apartment_number = form.apartment_number.data
            role = form.role.data

            # Check email exist
            is_exist = models.User.query.filter_by(email=email).first()
            if (is_exist):
                existing_user = db.session.query(models.User).filter(
                    models.User.email == email).first()
                existing_user.email = email
                existing_user.name = name
                existing_user.apartment_number = apartment_number
                existing_user.role = role
                existing_user.updated_date = datetime.datetime.now()
                db.session.commit()
                res = {
                    'id': existing_user.id,
                    'email': existing_user.email,
                    'name': existing_user.name,
                    'apartment_number': existing_user.apartment_number,
                    'role': existing_user.role,
                }

                return res
            else:
                raise APIError(404, 'Email is not exist')
        else:
            raise APIError(400, "Form is not valid")

    @login_required
    def delete(self, user_id):
        existing_user = db.session.query(
            models.User).filter_by(id=user_id).first()
        if (existing_user):
            existing_user.user_stage_rel = []
            db.session.delete(existing_user)
            db.session.commit()

        return jsonify(response='User has been deleted successfully')


class VisitorRecordsDatatables(Resource):
    @login_required
    def get(self):
        search = request.args.get('search[value]') or None
        start = int(request.args.get('start')) or 0
        length = int(request.args.get('length')) or 10
        action_button = '''
            <button type="button" rel="tooltip" class="btn btn-success edit">
                <i class="material-icons">visibility</i>
                <div class="ripple-container"></div>
            </button>
            '''
        res = []
        total_records = db.session.query(models.VisitorRecords).count()
        if search:
            query = models.VisitorRecords.query.filter(
                models.VisitorRecords.guest_name.contains(search)).order_by(models.VisitorRecords.created_date.desc())
        else:
            query = models.VisitorRecords.query.order_by(
                models.VisitorRecords.created_date.desc())

        filtered_records = query.all()

        if length:
            query = query.limit(length)
        if start:
            query = query.offset(start)

        for record in query:
            user = models.User.query.filter_by(id=record.owner_id).first()
            visitor_data = {
                "ID": record.id,
                "apartment_number": user.apartment_number,
                "owner_email": user.email,
                "guest_name": record.guest_name,
                "guest_id": record.guest_id,
                "guest_car_number": record.guest_car_number,
            }
            dt_data = {
                "DT_RowAttr": {
                    "data-id": record.id,
                    "data-visitor": json.dumps(visitor_data)
                },
            }
            res.append({**dt_data, **visitor_data,
                       **{'action': action_button}})
        return jsonify({
            "recordsTotal": total_records,
            "recordsFiltered": len(filtered_records),
            'data': res
        })


class RegisterVisitor(Resource):
    @login_required
    def post(self):
        form = RegisterVisitorForm()
        if form.validate_on_submit():
            owner_id = form.current_user_id.data
            guest_name = form.guest_name.data
            guest_email = form.guest_email.data
            guest_id = form.guest_id.data
            guest_car_number = form.guest_car_no.data
            no_of_guests = form.no_of_guests.data
            now = datetime.datetime.now()

            new_visitor = models.VisitorRecords(
                owner_id=owner_id,
                guest_name=guest_name,
                guest_id=guest_id,
                guest_email=guest_email,
                guest_car_number=guest_car_number,
                no_of_guests=no_of_guests,
                created_date=now,
                updated_date=now
            )
            db.session.add(new_visitor)
            db.session.commit()
            qr_code = generate_qr_code(
                json.dumps({'record_id': new_visitor.id}))
            res = {
                'id': new_visitor.id,
                'guest_name': new_visitor.guest_name,
                'guest_email': new_visitor.guest_email,
                'qr_code': qr_code,
            }
            send_email(new_visitor.guest_name,
                       new_visitor.guest_email, qr_code)
            return res
        else:
            raise APIError(400, "Form is not valid")


def generate_qr_code(data):
    try:
        # Encode to base64
        message_bytes = data.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')

        # save into physical path
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_H,
            box_size=10,
            border=4,
        )
        qr.add_data('localhost:5000/' + base64_message)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black",
                            back_color="white").convert('RGB')
        img.save("qr_code/{}.png".format(base64_message))
        print('generate QR code data: {}, qr_code:{}'.format(data, base64_message))
        return base64_message
    except Exception as e:
        raise APIError(500, 'Failed to register visitor')


def send_email(recipient_name, recipient_email, qr_code):
    try:
        msg = Message("Visistor Registration", recipients=[recipient_email])
        msg.body = 'Hi {}, your data has been registered as visitor'.format(
            recipient_name)
        with app.open_resource("qr_code/{}.png".format(qr_code)) as fp:
            msg.attach("qr_code.png", "image/png", fp.read())

        mail.send(msg)
        print('send QR code email to {}'.format(recipient_email))
    except Exception as e:
        raise APIError(500, 'Failed to send email to visitor')


# ------------- ERROR HANDLER -------------

@login_manager.unauthorized_handler
def unauthorized_access():
    next = url_for(request.endpoint, **request.view_args)
    return redirect(url_for('login', next=next))


class APIError(Exception):
    """All custom API Exceptions"""
    code = None
    description = None

    def __init__(self, code, description):
        self.code = code
        self.description = description


class APIAuthError(APIError):
    """Custom Authentication Error Class."""
    code = 403
    description = "Authentication Error"


@app.errorhandler(APIError)
def handle_exception(err):
    """Return custom JSON when APIError or its children are raised"""
    response = {"message": err.description}
    print("Exception: {}".format(str(err.description)))
    return make_response(jsonify(response), err.code)


@app.errorhandler(500)
def handle_exception(err):
    """Return JSON instead of HTML for any other server error"""
    print("Unknown Exception: {}".format(str(err)))
    response = {"message": "Internal Server Error"}
    return make_response(jsonify(response), 500)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return APIError(400, e)
