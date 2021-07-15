from app import db
from werkzeug.security import safe_str_cmp
from flask_login import UserMixin
import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), index=True, unique=True, nullable=False,)
    password = db.Column(db.String(80), index=True, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    apartment_number = db.Column(db.String(200))
    role = db.Column(db.String(100), nullable=False) # administrator, guard, apartment_owner
    created_date = db.Column(db.DateTime, index=False, unique=False,
                             nullable=False, default=datetime.datetime.now())
    updated_date = db.Column(db.DateTime, index=False, unique=False,
                             nullable=False, default=datetime.datetime.now())

    def check_password(self, password):
        # TODO password needs to be hashed
        return safe_str_cmp(password, self.password)

    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'apartment_number': self.apartment_number,
            'role': self.role,
            'created_date': self.created_date,
            'updated_date': self.updated_date,
        }


class VisitorRecords(db.Model):
    __tablename__ = 'visitor_records'

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    guest_name = db.Column(db.String(200), nullable=False)
    guest_id = db.Column(db.String(200), nullable=False)
    guest_email = db.Column(db.String(200), nullable=False)
    guest_car_number = db.Column(db.String(20))
    no_of_guests = db.Column(db.Integer, nullable=False)
    qr_code = db.Column(db.String(500), nullable=False, index=True, unique=True)
    created_date = db.Column(db.DateTime, index=False, unique=False,
                             nullable=False, default=datetime.datetime.now())
    updated_date = db.Column(db.DateTime, index=False, unique=False,
                             nullable=False, default=datetime.datetime.now())

    def to_dict(self):
        return {
            'id': self.id,
            'owner_id': self.owner_id,
            'guest_name': self.guest_name,
            'guest_id': self.guest_id,
            'guest_email': self.guest_email,
            'guest_car_number': self.guest_car_number,
            'no_of_guests': self.no_of_guests,
            'qr_code': self.qr_code,
            'created_date': self.created_date,
            'updated_date': self.updated_date,
        }
