from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timezone, timedelta
import os

app = Flask(__name__)
# Render의 DATABASE_URL 사용, 로컬은 SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///site.db')
# PostgreSQL 연결 시 필요한 URL 포맷 조정
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-jwt-secret-key')  # 환경 변수로 관리
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JSON_AS_ASCII'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, supports_credentials=True, origins=["http://localhost:8000"])

class User(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, onupdate=lambda:datetime.now(timezone.utc)) 

with app.app_context():
    db.create_all()  
    if not User.query.filter_by(username='admin').first():
        hashed_pw = bcrypt.generate_password_hash('1234').decode('utf-8')
        admin = User(username ='admin', password='hashed_pw', is_admin=True)
        db.session.add(admin)
        db.session.commit()

#인증 API
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username = username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify({"message": "로그인 성공", "acess_token": access_token, "is_admin": user.is_admin}),200
    return jsonify({"message": "로그인 실패"}),401

@app.route('/logout', methods=['POST'])
def logout():
    return jsonify({"message": "로그아웃 완료(클라이언트에서 토큰 삭제)"}),200

@app.route('/admin/status', methods=['GET'])
@jwt_required()
def admin_status():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return jsonify({"is_admin": user.is_admin}),200
        
#게시물 API
@app.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_admin:
        return jsonify({"message": "Admin권한이 필요합니다."}),403
    
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    author = data.get('author')

    new_post = Post(title=title, content=content, author=author)
    db.session.add(new_post)
    db.session.commit()
    return jsonify({"message": "게시물 생성 완료"}),201

@app.route('/posts', methods=['GET'])
def get_posts():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', None)

    query = Post.query
    if search:
        query = query.filter(Post.title.contains(search) | Post.content.contains(search))
        posts = query.paginate(page=page, per_page=per_page, error_out=False)
        posts_list = [{
            "id": post.id,
            "title": post.title,
            "content": post.content,
            "author": post.author,
            "created_at": post.created_at.isoformat()
        } for post in posts.items]

        return jsonify({
            "posts": posts_list,
            "total_pages": posts.pages,
            "current_pages": posts_page
        }),200

@app.route('/posts/<int:id>', methods=['PUT'])
@jwt_required()
def update_post(id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_admin:
        return jsonify({"message": "Admin 권한이 필요합니다."}),403
    
    post = Post.query.get(id)
    if not post:
        return jsonify({"message": "게시물을 찾을 수 없습니다."}),404
    
    data = request.get_json()
    post.title = data.get('title', post.title)
    post.content = data.get('content', post.content)
    post.author = data.get('author', post.author)
    db.session.commit()
    return jsonify({"message": "게시물 수정완료"}),200

@app.route('/posts/<int:id>', methods=['DELETE'])
def delete_post(id):
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.is_admin:
        return jsonify({"message": "Admin권한이 필요합니다."}),403
    post = Post.query.get(id)
    if not post:
        return jsonify({"message": "게시물을 찾을 수 없습니다."}),404
    
    db.session.delete(post)
    db.session.commit()
    return jsonify({"message": "게시물 삭제완료"}),200

if __name__ == '__main__':
    app.run(debug=True, port=5001)
        