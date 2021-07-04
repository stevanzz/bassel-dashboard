# Bassel Dashboard

This application is made using Python 3 & Flask library.
The context of this application is to create an Apartment Visitor Dashboard.

## Use Cases
- An apartment house owner would like to invite a guest to visit.
- The guest needs to register the information at the security station.
- The security station needs to verify the identity of the guest arriving.

## Requirements
  - The apartment owner issued a visit request. with the guest information.
    - name
    - id number
    - car number
    - number of guests
  - The guest receives a qr-code through an email.
  - The security guard can scan the code and retrieve the information about the visitor.

## Installation

requirements.txt file which contains all libraries used within the app.
Virtualenv is used to ensure clean environment before starting the app. (Not necessary)

```bash
# Install virtualenv, if not installed yet
pip install virtualenv

# New virtualenv (default python)
virtualenv venv

# New virtualenv (specify python3)
virtualenv -p python3 venv

# Activate virtualenv
venv\Scripts\activate

# Install requirements.txt
pip install -r requirements.txt
```

## Usage

1. Navigate to config/\__init__.py and set up the username, password and database name for the application.
2. Create a new Postgres DB with the same details that you have put in config file.
3. Perform below commands to auto-initialize DB schemas
```bash
# Execute this command to initialize DB schemas
python .\manage.py db init
python .\manage.py db migrate
python .\manage.py db upgrade
```
4. Do a manual insert to start with minimum data in the database
```sql
INSERT INTO public.user (email, name, password, role, created_date, updated_date) VALUES ('admin@gmail.com', 'admin', 'pass', 'administrator', NOW(), NOW());
INSERT INTO public.user (email, name, password, role, created_date, updated_date) VALUES ('guard1@gmail.com', 'guard1', 'pass', 'guard', NOW(), NOW());
INSERT INTO public.user (email, name, password, apartment_number, role, created_date, updated_date) VALUES ('user1@gmail.com', 'user1', 'pass', 'A-12-21', 'apartment_owner', NOW(), NOW());
```
5. Mail Server Configuration (you can register your own mail server for free in  [mailtrap.io](https://mailtrap.io/))
```python
MAIL_SERVER = 'smtp.mailtrap.io'
MAIL_PORT = 2525
MAIL_USERNAME = '1d184d2b3791cb' # to be changed
MAIL_PASSWORD = 'b6c189ec5cb071' # to be changed
MAIL_USE_TLS = True
MAIL_USE_SSL = False
MAIL_DEFAULT_SENDER = 'dev@gmail.com'
```
6. Run the app
```bash
# Execute this command and application will run on http://localhost:5000/
python .\manage.py runserver
```

## Endpoints
1. Login Page (Entrypoint)
[http://localhost:5000/login](http://localhost:5000/login)

2. User List Page (only accessible for Admin)
[http://localhost:5000/users](http://localhost:5000/users)

3. Visitor Records Page (only accessible for Admin and Guard)
[http://localhost:5000/visitor-records](http://localhost:5000/visitor-records)

4. Register Visitor Page (only accessible for Admin and Apartment Owner)
[http://localhost:5000/register-visitor](http://localhost:5000/register-visitor)


## Future Enhancements
- [ ] Individual schema for Apartment (unit number, owner email, owner name, tenant email, tenant name)
- [ ] Implement refresh token for better security
- [ ] Password hashing, reset password, forgot password
- [ ] Email HTML template
- [ ] Cloud storage to store QR code

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.


