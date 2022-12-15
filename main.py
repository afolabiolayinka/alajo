import os
import time
from flask import Flask, abort, request, jsonify, g, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta

# Initialize variables
app = Flask(__name__)
app.config['SECRET_KEY'] = 'alajo2022'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///alajo.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# Extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String)
    business_name = db.Column(db.String)

    def __init__(self):
        return

    def to_json(self):
        return {
            'id': self.id,
            'email': self.email,
            'business_name': self.business_name
        }

    def hash_password(self, password):
        self.password = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password, password)


class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String, unique=True, nullable=False)
    first_name = db.Column(db.String)
    last_name = db.Column(db.String)
    ban = db.Column(db.String)
    balance = db.Column(db.String)

    def __init__(self):
        return

    def to_json(self):
        return {
            'id': self.id,
            'code': self.code,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'ban': self.ban
        }


class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, nullable=False)
    transaction_no = db.Column(db.String, unique=True, nullable=False)
    effect = db.Column(db.String, nullable=False)
    amount = db.Column(db.String, nullable=False)
    created = db.Column(db.String, nullable=False)

    def __init__(self):
        return

    def to_json(self):
        return {
            'id': self.id,
            'customer_id': self.customer_id,
            'transaction_no': self.transaction_no,
            'effect': self.effect,
            'amount': self.amount,
            'created': self.created,
        }


@app.route("/setup", methods=['POST'])
def setup():
    db.session.execute("DROP TABLE IF EXISTS users;")
    db.session.execute("DROP TABLE IF EXISTS customers;")
    db.session.execute("DROP TABLE IF EXISTS transactions;")
    db.session.execute(
        '''
        CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,  
        created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        business_name TEXT NOT NULL
        );
        '''
    )
    db.session.execute(
        '''
        CREATE TABLE customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,  
        created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        code TEXT UNIQUE NOT NULL,  
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        ban TEXT NOT NULL,
        balance NUMERIC NOT NULL
        );
        '''
    )
    db.session.execute(
        '''
        CREATE TABLE transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        customer_id INTEGER NOT NULL,
        transaction_no TEXT UNIQUE NOT NULL,  
        effect INTEGER NOT NULL,
        amount NUMERIC NOT NULL,
        FOREIGN KEY (customer_id) REFERENCES customers (id)
        );
        '''
    )

    user = User()
    user.email = "business@alajo.app"
    user.hash_password("pass1234")
    user.business_name = "Alajo Limited"
    db.session.add(user)
    db.session.commit()

    customer = Customer()
    customer.id = 1
    customer.code = "CRM0001"
    customer.first_name = "John"
    customer.last_name = "Doe"
    customer.ban = "20020001"
    customer.balance = 52000
    db.session.add(customer)
    db.session.commit()

    customer = Customer()
    customer.id = 2
    customer.code = "CRM0002"
    customer.first_name = "Jane"
    customer.last_name = "Doe"
    customer.ban = "20020002"
    customer.balance = 82500
    db.session.add(customer)
    db.session.commit()

    transaction = Transaction()
    transaction.transaction_no = "TXN002"
    transaction.customer_id = 1
    transaction.amount = 20000
    transaction.effect = 1
    transaction.created = "2022-12-12"
    db.session.add(transaction)
    db.session.commit()

    transaction = Transaction()
    transaction.transaction_no = "TXN003"
    transaction.customer_id = 1
    transaction.amount = 15000
    transaction.effect = 2
    transaction.created = "2022-12-14"
    db.session.add(transaction)
    db.session.commit()

    transaction = Transaction()
    transaction.transaction_no = "TXN004"
    transaction.customer_id = 1
    transaction.amount = 500
    transaction.effect = 2
    transaction.created = "2022-12-15"
    db.session.add(transaction)
    db.session.commit()

    transaction = Transaction()
    transaction.transaction_no = "TXN005"
    transaction.customer_id = 2
    transaction.amount = 55000
    transaction.effect = 1
    transaction.created = "2022-12-11"
    db.session.add(transaction)
    db.session.commit()

    transaction = Transaction()
    transaction.transaction_no = "TXN012"
    transaction.customer_id = 2
    transaction.amount = 7000
    transaction.effect = 2
    transaction.created = "2022-12-1"
    db.session.add(transaction)
    db.session.commit()

    return jsonify({'message': 'Setup complete'})


# decorator for verifying the JWT
def token_requiredx(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {
                "message": "Authentication Token is missing!",
                "data": None,
                "error": "Unauthorized"
            }, 401
        try:
            data = jwt.decode(
                token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = User.query.filter_by(email=data['email']).first()

            if current_user is None:
                return {
                    "message": "Invalid Authentication token!",
                    "data": None,
                    "error": "Unauthorized"
                }, 401
            if not current_user["active"]:
                abort(403)
        except Exception as e:
            return {
                "message": "Something went wrong",
                "data": None,
                "error": str(e)
            }, 500

        return f(current_user, *args, **kwargs)
    return decorated

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

        token = None

        token = request.headers["Authorization"].split(" ")[1]

        if not token:
            return jsonify({'message': 'a valid token is missing'})
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(email=data['email']).first()
        except Exception as e:
            return {
                "message": "Something went wrong",
                "data": None,
                "error": str(e)
            }, 500

        return f(current_user, *args, **kwargs)
    return decorator


@auth.verify_password
def verify_password(username_or_token, password):
    # first try token
    user = User.verify_auth_token(username_or_token)
    # then check for username and password pair
    if not user:
        user = User.query.filter_by(email=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/auth/register', methods=['POST'])
def register():
    email = request.json.get('email')
    password = request.json.get('password')
    business_name = request.json.get('business_name')
    # Check for blank requests
    if email is None or password is None:
        return (jsonify({'message': 'Email address and password is required'}), 400)
    # Check for existing users
    if User.query.filter_by(email=email).first() is not None:
        return (jsonify({'message': 'Email address already exist'}), 400)
    user = User()
    user.email = email
    user.hash_password(password)
    user.business_name = business_name
    db.session.add(user)
    db.session.commit()
    return (jsonify({'email': user.email}), 201)


@app.route('/auth/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()

    # Check for existing users
    if not user:
        return (jsonify({'message': 'Email address not found'}), 400)

    if not check_password_hash(user.password, password):
        return (jsonify({'message': 'Password do not match'}), 400)

    # generates the JWT Token
    token = jwt.encode({
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }, app.config['SECRET_KEY'])

    return make_response(jsonify({'token': token}), 201)


@app.route('/app/whoami', methods=['GET'])
@token_required
def whoami(current_user):
    return jsonify({'message': 'It is done {}'.format(current_user.email)})


@app.route("/app/users", methods=["GET"])
@token_required
def get_users(current_user):
    users = User.query.all()
    return jsonify([user.to_json() for user in users])


@app.route("/app/customers", methods=["GET"])
@token_required
def get_customers(current_user):
    customers = Customer.query.all()
    return jsonify([customer.to_json() for customer in customers])


@app.route("/app/customer_by_ban/<string:ban>", methods=["GET"])
@token_required
def get_customers_by_ban(current_user,ban):
    customer = Customer.query.filter_by(ban=ban).first()
    return jsonify({'customer': customer.to_json()}, 200)


@app.route("/app/transactions_by_ban/<string:ban>", methods=["GET"])
@token_required
def get_transactions_by_ban(current_user,ban):
    customer = Customer.query.filter_by(ban=ban).first()
    transactions = Transaction.query.filter_by(customer_id=customer.id)
    return jsonify([transaction.to_json() for transaction in transactions])


if __name__ == "__main__":
    if not os.path.exists('alajo.sqlite'):
        db.create_all()
    app.run(debug=True)
