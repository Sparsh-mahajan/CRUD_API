from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import jwt
from functools import wraps
import uuid
import os

base_dir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = str(uuid.uuid1())
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, 'db.sqlite')
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    todos = db.relationship('Todo', backref='owner')


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String, nullable=False)
    task = db.Column(db.String, nullable=False)
    date_added = db.Column(db.Date, default=datetime.utcnow)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


def token_required(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = None
        current_user = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({
                'error': 'could not authenticate',
                'message': 'token is missing'
            }), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(email=data['email']).first()
        finally:
            if not current_user:
                return jsonify({
                    'error': 'could not authenticate',
                    'message': 'token is invalid'
                }), 401
            return func(current_user, *args, **kwargs)

    return decorated


@app.route("/users/", methods=["GET"])
@token_required
def get_users(current_user):
    if not current_user.is_admin:
        return jsonify({
            'error': 'cannot perform the function',
            'message': 'only admins are authorised to call this endpoint'
        })
    return jsonify([
        {'name': user.name, 'public_id': user.public_id, 'email': user.email, 'is_admin': user.is_admin}
        for user in User.query.all()
    ]), 200


@app.route("/users/<user_id>/", methods=["GET"])
@token_required
def get_user(current_user, user_id):
    if current_user.public_id != user_id:
        return jsonify({
            'error': 'cannot perform the function',
            'message': 'sensitive information cannot be accessed without logging in'
        })
    user = User.query.filter_by(public_id=user_id).first_or_404()
    return jsonify({
        'name': user.name, 'public_id': user.public_id, 'email': user.email, 'is_admin': user.is_admin
    }), 200


@app.route("/users/", methods=["POST"])
def create_user():
    data = request.get_json()
    if 'name' not in data or 'email' not in data or 'password' not in data:
        return jsonify({
            'error': 'Bad request',
            'message': 'email or name or password not provided'
        }), 400

    name = data['name']
    email = data['email']
    public_id = str(uuid.uuid1())
    hashed_password = generate_password_hash(data['password'], 'scrypt')

    user = User(public_id=public_id, name=name, email=email, password=hashed_password, is_admin=False)
    db.session.add(user)
    db.session.commit()

    return jsonify({
        'name': user.name, 'public_id': user.public_id, 'email': user.email, 'is_admin': user.is_admin
    }), 201


@app.route("/users/<user_id>/", methods=["PUT"])
@token_required
def update_user(current_user, user_id):
    if current_user.public_id != user_id:
        return jsonify({
            'error': 'cannot perform the function',
            'message': 'sensitive information cannot be accessed without logging in'
        })
    user = User.query.filter_by(public_id=user_id).first_or_404()
    data = request.get_json()

    if 'name' not in data or 'email' not in data:
        return jsonify({
            'error': 'Bad request',
            'message': 'email or name not given'
        }), 400

    name = data['name']
    email = data['email']

    user.name = name
    user.email = email
    db.session.commit()

    return jsonify({
        'name': user.name, 'public_id': user.public_id, 'email': user.email, 'is_admin': user.is_admin
    }), 200


@app.route("/users/<user_id>/", methods=["DELETE"])
@token_required
def delete_user(current_user, user_id):
    if current_user.public_id != user_id:
        return jsonify({
            'error': 'cannot perform the function',
            'message': 'sensitive information cannot be accessed without logging in'
        })
    user = User.query.filter_by(public_id=user_id).first_or_404()
    db.session.delete(user)
    db.session.commit()
    return jsonify({
        'message': 'successfully deleted data'
    }), 200


@app.route("/todos/", methods=["GET"])
@token_required
def get_todos(current_user):
    user_email = current_user.email
    user = User.query.filter_by(email=user_email).first()
    if not user:
        return jsonify({
            'error': 'bad request',
            'message': 'no user found for the given email id'
        }), 400

    return jsonify([{'public_id': todo.public_id, 'task': todo.task,
                     'date_added': todo.date_added, 'completed': todo.completed,
                     'owner': {
                         'name': todo.owner.name,
                         'public_id': todo.owner.public_id,
                         'email': todo.owner.email}
                     } for todo in Todo.query.filter_by(user_id=user.id).all()]), 200


@app.route("/todos/<todo_id>/", methods=["GET"])
@token_required
def get_todo(current_user, todo_id):
    todo = Todo.query.filter_by(public_id=todo_id).first_or_404()
    if current_user.id != todo.user_id:
        return jsonify({
            'error': 'cannot perform the function',
            'message': 'sensitive information cannot be accessed without logging in'
        })
    return jsonify({'public_id': todo.public_id, 'task': todo.task,
                    'date_added': todo.date_added, 'completed': todo.completed,
                    'owner': {
                        'name': todo.owner.name,
                        'public_id': todo.owner.public_id,
                        'email': todo.owner.email
                    }
                    }), 200


@app.route("/todos/", methods=["POST"])
@token_required
def create_todo(current_user):
    data = request.get_json()
    if 'task' not in data:
        return jsonify({
            'error': 'bad request',
            'message': 'task not present'
        })

    task = data['task']
    public_id = str(uuid.uuid1())
    date_added = data.get('date_added', datetime.utcnow())
    completed = data.get('completed', False)

    todo = Todo(public_id=public_id, task=task, date_added=date_added, completed=completed, user_id=current_user.id)
    db.session.add(todo)
    db.session.commit()

    return jsonify({'public_id': todo.public_id, 'task': todo.task,
                    'date_added': todo.date_added, 'completed': todo.completed,
                    'owner': {
                        'name': todo.owner.name,
                        'public_id': todo.owner.public_id,
                        'email': todo.owner.email
                    }
                    }), 201


@app.route("/todos/<todo_id>/", methods=["PUT"])
@token_required
def update_todo(current_user, todo_id):
    todo = Todo.query.filter_by(public_id=todo_id).first_or_404()

    if current_user.id != todo.user_id:
        return jsonify({
            'error': 'cannot perform the function',
            'message': 'sensitive information cannot be accessed without logging in'
        })

    data = request.get_json()
    if 'task' not in data:
        return jsonify({
            'error': 'bad request',
            'message': 'updated task not provided for todo with the given public id'
        }), 400

    todo.task = data['task']
    if 'completed' in data:
        todo.completed = data['completed']
    db.session.commit()

    return jsonify({'public_id': todo.public_id, 'task': todo.task,
                    'date_added': todo.date_added, 'completed': todo.completed,
                    'owner': {
                        'name': todo.owner.name,
                        'public_id': todo.owner.public_id,
                        'email': todo.owner.email
                    }
                    }), 200


@app.route("/todos/<todo_id>/", methods=['DELETE'])
@token_required
def delete_todo(current_user, todo_id):
    todo = Todo.query.filter_by(public_id=todo_id).first_or_404()

    if current_user.id != todo.user_id:
        return jsonify({
            'error': 'cannot perform the function',
            'message': 'sensitive information cannot be accessed without logging in'
        })

    db.session.delete(todo)
    db.session.commit()
    return jsonify({
        'message': 'successfully deleted data'
    }), 200


@app.route("/login/")
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return jsonify({
            'error': 'could not authenticate',
            'message': 'login required'
        }), 401

    user = User.query.filter_by(email=auth.username).first()
    if not user:
        return jsonify({
            'error': 'could not authenticate',
            'message': 'no user found with the provided email ID'
        }), 401

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({
            'email': user.email, 'exp': datetime.utcnow() + timedelta(minutes=30)}, app.config['SECRET_KEY'],
            algorithm="HS256")
        return jsonify({
            'token': token
        })

    return jsonify({
        'error': 'could not authenticate',
        'message': 'password does not match'
    }), 401


if __name__ == '__main__':
    app.run(debug=True)
