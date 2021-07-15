import datetime


class Config(object):
    DEBUG = False
    TESTING = False
    DATABASE_URI = 'sqlite:///:memory:'


class ProductionConfig(Config):
    pass
    # DATABASE_URI = 'mysql://user@localhost/foo'


class StagingConfig(Config):
    DEBUG = True


class TestingConfig(Config):
    TESTING = True


class DevelopmentConfigJWT(Config):
    ENV = 'Development'
    DEBUG = True
    DEVELOPMENT = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:openpgpwd@localhost:5432/bassel'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_TOKEN_LOCATION = ['cookies']
    JWT_SECRET_KEY = 'super-secret'  # To be changed in different environment
    JWT_ACCESS_TOKEN_EXPIRES = False
    JWT_COOKIE_SECURE = False
    JWT_COOKIE_CSRF_PROTECT = True
    JWT_ACCESS_CSRF_HEADER_NAME = "X-CSRF-TOKEN-ACCESS"
    JWT_REFRESH_CSRF_HEADER_NAME = "X-CSRF-TOKEN-REFRESH"
    MAIL_SERVER = 'smtp.mailtrap.io'
    MAIL_PORT = 2525
    MAIL_USERNAME = '1d184d2b3791cb'  # personal username
    MAIL_PASSWORD = 'b6c189ec5cb071'  # personal password
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_DEFAULT_SENDER = 'dev@gmail.com'


class DevelopmentConfig(Config):
    ENV = 'Development'
    DEBUG = True
    DEVELOPMENT = True
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:openpgpwd@localhost:5432/bassel'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = '7d134cfb70683a0ca33530a778f4e630'
    MAIL_SERVER = 'smtp.mailtrap.io'
    MAIL_PORT = 2525
    MAIL_USERNAME = '1d184d2b3791cb'  # personal username
    MAIL_PASSWORD = 'b6c189ec5cb071'  # personal password
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_DEFAULT_SENDER = 'dev@gmail.com'
