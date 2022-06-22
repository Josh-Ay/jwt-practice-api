import json
import os
import re

from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token
)
from bson import json_util
from bson.objectid import ObjectId
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY")

jwt = JWTManager(app)
client = MongoClient(os.environ.get('MONGO_DB_URI'))

db = client.sloovi_db
users = db.users
templates = db.templates

EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")


@app.route("/register", methods=["POST"])
def register():
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form.get('email')
    password = request.form.get('password')

    if first_name is None or len(first_name) < 1:
        return jsonify("first_name is required"), 400

    if last_name is None or len(last_name) < 1:
        return jsonify("last_name is required"), 400

    if email is None or len(email) < 1:
        return jsonify("email is required"), 400

    if len(email) > 1 and not EMAIL_REGEX.match(email):
        return jsonify("Please enter a valid email")

    if password is None or len(password) < 1:
        return jsonify("password is required"), 400

    existing_user = users.find_one({"email": email})

    if existing_user is not None:
        return jsonify("Email already registered"), 409

    users.insert_one({
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "password": generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=10,
        ),
    })

    access_token = create_access_token(identity={"email": email})

    return jsonify(access_token), 200


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    if email is None or len(email) < 1:
        return jsonify("email required"), 400

    if password is None or len(password) < 1:
        return jsonify("password required"), 400

    found_user = users.find_one({"email": email})

    if found_user is None:
        return jsonify("Email not registered. Register?"), 404

    if not check_password_hash(found_user["password"], password):
        return jsonify("Email and password mismatch."), 401

    access_token = create_access_token(identity={"email": email})

    return jsonify(access_token), 200


@app.route("/template", methods=["GET", "POST"])
@jwt_required()
def template():
    if request.method == "POST":
        template_name = request.form.get('template_name')
        subject = request.form.get('subject')
        body = request.form.get('body')

        if template_name is None or len(template_name) < 1:
            return jsonify("template_name required"), 400

        if subject is None or len(subject) < 1:
            return jsonify("subject required"), 400

        if body is None or len(body) < 1:
            return jsonify("body required"), 400

        templates.insert_one({
            "template_name": template_name,
            "subject": subject,
            "body": body,
        })

        return jsonify("Successfully added template!"), 200

    all_templates = templates.find({})

    return jsonify(json.loads(json_util.dumps(all_templates))), 200


@app.route("/template/<template_id>", methods=["GET", "PUT", "DELETE"])
@jwt_required()
def get_single_template(template_id):
    if not ObjectId.is_valid(template_id):
        return jsonify("Please enter a valid template id"), 400

    if request.method == "PUT":
        template_name = request.form.get('template_name')
        subject = request.form.get('subject')
        body = request.form.get('body')

        if template_name is None or len(template_name) < 1:
            return jsonify("template_name required"), 400

        if subject is None or len(subject) < 1:
            return jsonify("subject required"), 400

        if body is None or len(body) < 1:
            return jsonify("body required"), 400

        templates.update_one(
            {"_id": ObjectId(template_id)},
            {
                "$set":
                {
                    "template_name": template_name,
                    "subject": subject,
                    "body": body
                }
            }
        )
        return jsonify("Successfully updated template"), 200

    if request.method == "DELETE":
        templates.delete_one({"_id": ObjectId(template_id)})
        return jsonify("Successfully deleted template!"), 200

    single_template = templates.find_one({"_id": ObjectId(template_id)})

    return jsonify(json.loads(json_util.dumps(single_template))), 200


if __name__ == '__main__':
    app.run(debug=True)
