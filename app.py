# from flask import Flask,request, url_for, jsonify
# from markupsafe import escape

# app = Flask(__name__)

# @app.route("/")
# def hello_world():
#     return "<p> Hello world </p>"

# @app.route("/hello/")
# def hello():
#     name = request.args.get("name", "Furqan")
#     return f'hello, {name}'

# # @app.route("/user/<username>")
# # def show_user_profile(username):
# #     return f"{username}\'s profile"

# @app.route("/post/<int:post_id>")
# def show_post(post_id):
#     return f"post number: {post_id}"

# @app.route("/subpath/<path:subpath>")
# def r_subpath(subpath):
#     return f"path: {escape(subpath)}"

# @app.route('/user/<username>')
# def profile(username):
#     return f'{username}\'s profile'

# @app.route('/home')
# def home():
#     return jsonify({"Welcome": "To the flask API."})


# with app.test_request_context():
#     # print(url_for("hello_world"))
#     # print(url_for('hello', next="/", name = "rum"))
#     # print(url_for("show_user_profile", username="Romeo"))
#     # print(url_for('show_post', post_id="1"))
#     # print(url_for('r_subpath', subpath="File structure"))
#     print(url_for('profile', username='John Doe'))


# books = [
# {'id': 1, 'title': 'The Great Gatsby', 'author': 'F. Scott Fitzgerald'},
# {'id': 2, 'title': 'To Kill a Mockingbird', 'author': 'Harper Lee'},
# {'id': 3, 'title': '1984', 'author': 'George Orwell'},
# {'id': 4, 'title': 'The Amerian Life','authou': 'Bengemin Franklin'}
# ]


# def find_book(id):
#     return next((book for book in books if book['id'] == id), None)

# @app.route('/books', methods=['GET'])
# def get_books():
#     return jsonify(books)

# @app.route('/books/<int:id>', methods=['GET'])
# def get_boook_by_id(id):
#     book = find_book(id)

#     if not book:
#         print('Book with the id', id, 'was not found!')
#         return f'Book With id {id} was not found'
#         # return jsonify({'Error': 'The book with the provided {id} was not found'}), 404

#     return jsonify({"book": book})

# @app.route('/books', methods=['POST'])
# def create_book():
#     new_book=[
#         {
#             'id': len(books),
#             'title': request.json['title'],
#             'author': request.json['author']
#         }
#     ]

#     books.append(new_book)

#     return jsonify(new_book), 201

# @app.route('/books/<int:id>', methods=['PUT'])
# def update_book():
#     book = find_book(id)
#     if not book:
#         return jsonify({'message': 'The book was not found'}), 404
#     book['title'] = request.json.get('title', book['title'])
#     book['author'] = request.json.get('author', book['author'])
#     return jsonify({"book": book})

# @app.route('/books/<int:id>', methods=['DELETE'])
# def delete_book(id):
#     global books

#     book = [(book for book in books if book['id'] != id)]
#     return jsonify({"message":"Book deleted"})

# if __name__ == "__main__":
#     app.run(debug=True)


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


