from flask_script import Manager, Server
from flask_migrate import Migrate, MigrateCommand
from app import db, app

# manage.py db stamp heads is very use full when some error on migration an upgrade

migrate = Migrate(app, db, compare_type=True)
manager = Manager(app)
manager.add_command('db', MigrateCommand)
manager.add_command("runserver", Server(host='0.0.0.0', port='5000'))

if __name__ == '__main__':
    manager.run()
