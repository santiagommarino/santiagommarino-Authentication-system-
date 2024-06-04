"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
import hashlib


api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route('/singup', methods=(['POST']))
def singup():
    body = request.get_json()
    user_email = body['email']
    user_password = hashlib.sha256(body['password'].encode('utf-8'))hexdigest()
    user = User(email=user_email, password=user_password)
    db.session.add(user)
    db.session.commit()

@api.route('/login', methods=(['POST']))
def login():
    body = request.get_json()
    user_email = body['email']
    user_password = hashlib.sha256(body['password'].encode('utf-8'))hexdigest()
    user = User.query.filter_by(email=user_email). first()
    if user and user.password = user_password
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token)

@api.route('/user', methods=(['GET']))
@jwt_required()
def get_user():
    user_id = get_jwt_identity()
    user = User.query.get(get_user)
    return jsonify(email=user.email, name=user.name)
