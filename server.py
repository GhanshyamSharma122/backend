from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename

# Initialize Flask App
app = Flask(__name__)
CORS(app)  # Enable CORS for Flutter integration

# Configure Database (Change this to your actual DB URI)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = "your_secret_key"  # Change this in production

# Initialize Extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Configure Image Upload Folder
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# =======================
# DATABASE MODELS
# =======================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.Text, nullable=False)
    contact_number = db.Column(db.String(15), nullable=False)
    contact_details = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    hostel_location = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


# =======================
# AUTHENTICATION ROUTES
# =======================
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    new_user = User(username=data['username'], email=data['email'], password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()

    if user and bcrypt.check_password_hash(user.password_hash, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({'token': access_token, 'user_id': user.id}), 200

    return jsonify({'message': 'Invalid email or password'}), 401
@app.route('/', methods=['POST'])
def defaul():
    return 'hello man'

# =======================
# PRODUCT MANAGEMENT ROUTES
# =======================
@app.route('/add_product', methods=['POST'])
@jwt_required()
def add_product():
    data = request.form
    user_id = get_jwt_identity()

    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400

    image = request.files['image']
    filename = secure_filename(image.filename)
    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image.save(image_path)

    new_product = Product(
        name=data['name'],
        price=float(data['price']),
        description=data['description'],
        contact_number=data['contact_number'],
        contact_details=data['contact_details'],
        category=data['category'],
        hostel_location=data['hostel_location'],
        image_url=filename,
        user_id=user_id
    )
    db.session.add(new_product)
    db.session.commit()

    return jsonify({'message': 'Product added successfully'}), 201


@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    products_list = [{
        'id': p.id,
        'name': p.name,
        'price': p.price,
        'description': p.description,
        'contact_number': p.contact_number,
        'contact_details': p.contact_details,
        'category': p.category,
        'hostel_location': p.hostel_location,
        'image_url': f"http://localhost:5000/uploads/{p.image_url}" if p.image_url else None,
        'user_id': p.user_id
    } for p in products]

    return jsonify(products_list), 200


@app.route('/product/<int:product_id>', methods=['GET'])
def get_product(product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    product_data = {
        'id': product.id,
        'name': product.name,
        'price': product.price,
        'description': product.description,
        'contact_number': product.contact_number,
        'contact_details': product.contact_details,
        'category': product.category,
        'hostel_location': product.hostel_location,
        'image_url': f"http://localhost:5000/uploads/{product.image_url}" if product.image_url else None,
        'user_id': product.user_id
    }

    return jsonify(product_data), 200


@app.route('/product/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    user_id = get_jwt_identity()
    product = Product.query.get(product_id)

    if not product:
        return jsonify({'error': 'Product not found'}), 404

    if product.user_id != user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    db.session.delete(product)
    db.session.commit()

    return jsonify({'message': 'Product deleted successfully'}), 200


# =======================
# SERVE UPLOADED IMAGES
# =======================
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


# =======================
# RUN SERVER
# =======================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)
