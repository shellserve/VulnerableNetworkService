import os
import time
import json
import base64
import hashlib

from flask import Flask, request, jsonify, abort, g
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth

from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = "BnZr723B[.MFTnVV"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///db.sqlite"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

db = SQLAlchemy(app)
auth = HTTPBasicAuth()

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(32), index = True)
    account_type = db.Column(db.Integer)

    password_hash = db.Column(db.String(64))

    passwords = db.relationship('Password', backref='user', lazy='dynamic')

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def gen_auth_token(self, expires_in = 1200):
        s = Serializer(app.config['SECRET_KEY'],
                    expires_in=expires_in)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        return User.query.get(data['id'])

class Password(db.Model):
    __tablename__ = "passwords"
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    service = db.Column(db.String(128))
    enc_password = db.Column(db.String(256))
    iv = db.Column(db.String(64))

    def encrypt_pass(self, raw_password, master_password):
        encryption_key = hashlib.sha256(master_password.encode('utf-8')).digest()
        cipher = AES.new(encryption_key, AES.MODE_CBC)
        enc_password = cipher.encrypt(pad(raw_password.encode(), AES.block_size))
        self.iv = base64.b64encode(cipher.iv).decode('utf-8')
        self.enc_password = base64.b64encode(enc_password).decode('utf-8')

    def unencrypt_pass(self, master_password):
        try:
            encryption_key = hashlib.sha256(master_password.encode('utf-8')).digest()
            iv = base64.b64decode(self.iv)
            enc_password = base64.b64decode(self.enc_password)
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            cipher_plain = unpad(cipher.decrypt(enc_password), AES.block_size)
            return cipher_plain

        except ValueError or KeyError:
            return "Decryption Failiure."

@auth.verify_password
def verify_password(username_or_token, password):
    user = User.verify_token(username_or_token)
    if not user:
        user = User.query.filter_by(username = username_or_token).first()
        if not user or not user.check_password(password):
            return False
    g.user = user
    return True

@app.route('/', methods=['GET'])
def get_MOTD():
    return jsonify({"motd": "Welcome to your password keeper!"})

@app.route('/user/create', methods=['POST'])
def create_user():
    username = request.json.get('username')
    password = request.json.get('password')
    account_type = request.json.get('acc_type')

    if username is None or password is None:
        return (jsonify({'message':'Missing username or password'}))
    if User.query.filter_by(username=username).first():
        return (jsonify({'message':'User already exists'}))
    if account_type is None:
        account_type = 1

    user = User(username=username, account_type=account_type)
    user.hash_password(password)

    db.session.add(user)
    db.session.commit()

    return (jsonify({'username': user.username}), 201)

@app.route('/user/login', methods=['GET'])
@auth.login_required
def get_token():
    token = g.user.gen_auth_token()
    return jsonify({ 'token': token.decode('ascii')})

@app.route('/password/set', methods=['POST'])
@auth.login_required
def set_password():
    user_id = g.user.id
    service = request.json.get('service')
    
    if service is None or request.json.get('password') is None:
        return (jsonify({'No Service and/or password Given!'}))

    password = Password(user_id=user_id, service=service)
    password.encrypt_pass(request.json.get('password'), g.user.password_hash)

    db.session.add(password)
    db.session.commit()

    return (jsonify({'message':f'Password added for service {service.capitalize()}'}))

@app.route('/password/get/<service>', methods=['GET'])
@auth.login_required
def get_password(service):
    if service is None:
        return jsonify({'message':'No service given!'})
    service = service.lower()
    password = db.session.query(Password).\
        filter(Password.user.has(User.id == g.user.id)).\
        filter(Password.service == service).first()

    return (jsonify({'password':f'{password.unencrypt_pass(g.user.password_hash)}'}))

@app.route('/password/get/all', methods=['GET'])
@auth.login_required
def get_all_pass():
    passwords = []
    if g.user.account_type == 1:##Is Normal User
        for password in db.session.query(Password).filter(Password.user.has(User.id == g.user.id)).all():
            passwords.append({'service':str(password.service),'password':str(password.unencrypt_pass(g.user.password_hash))})
        return (jsonify({'passwords':passwords}))

    if g.user.account_type == 0:##Is Admin User
        for password,user in db.session.query(Password,User).filter(User.id==Password.user_id).all():
            passwords.append({'service':str(password.service),'password':str(password.unencrypt_pass(user.password_hash))})
        return (jsonify({'passwords':passwords}))

    else:
        return (jsonify({'message': f'invalid account_type: {g.user.account_type} contact administrator'}))

if __name__ == "__main__":
    if not os.path.exists('db.sqlite'):
        db.create_all()

    app.run(debug=True)
