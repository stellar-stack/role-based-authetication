from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt
)
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret-key"
jwt = JWTManager(app)


users_db = {
    "admin": {
        "password": generate_password_hash("admin123"),
        "role": "admin"
    },
    "editor": {
        "password": generate_password_hash("editor123"),
        "role": "editor"
    },
    "viewer": {
        "password": generate_password_hash("viewer123"),
        "role": "viewer"
    }
}


def role_required(allowed_roles):
    def wrapper(fn):
        @jwt_required()
        def decorator(*args, **kwargs):
            claims = get_jwt()
            user_role = claims.get("role")
            if user_role not in allowed_roles:
                return jsonify({"msg": "Access forbidden: insufficient role"}), 403
            return fn(*args, **kwargs)
        decorator.__name__ = fn.__name__
        return decorator
    return wrapper


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data or "username" not in data or "password" not in data:
        return jsonify({"msg": "Username and password required"}), 400

    user = users_db.get(data["username"])
    if not user or not check_password_hash(user["password"], data["password"]):
        return jsonify({"msg": "Invalid credentials"}), 401


    access_token = create_access_token(
        identity=data["username"],
        additional_claims={"role": user["role"]},
        expires_delta=datetime.timedelta(hours=1)
    )
    return jsonify(access_token=access_token)


@app.route("/admin-data", methods=["GET"])
@role_required(["admin"])
def admin_data():
    return jsonify({"data": "Sensitive admin data"})

@app.route("/edit-data", methods=["GET"])
@role_required(["admin", "editor"])
def edit_data():
    return jsonify({"data": "Editable content"})

@app.route("/view-data", methods=["GET"])
@role_required(["admin", "editor", "viewer"])
def view_data():
    return jsonify({"data": "Public viewable content"})

if __name__ == "__main__":
    app.run(debug=True)



