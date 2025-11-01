from flask import Flask, render_template, redirect, request, url_for, flash, session
from flask_scss import Scss
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os

app = Flask(__name__)
Scss(app)

app.config['SECRET_KEY'] = 'your-secret-key-change-this'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///foodie.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

db = SQLAlchemy(app)

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())
    posts = db.relationship('Post', backref='author', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f"User {self.username}"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dish_name = db.Column(db.String(200), nullable=False)
    ingredients = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    image_filename = db.Column(db.String(300))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=db.func.current_timestamp())

    def __repr__(self):
        return f"Post {self.dish_name}"


with app.app_context():
    db.create_all()


# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


# Routes
@app.route('/')
def index():
    try:
        posts = Post.query.order_by(Post.created.desc()).all()
        return render_template('index.html', posts=posts)
    except Exception as e:
        print(f"Error in index: {e}")
        return render_template('index.html', posts=[])


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # Validation
        if not username or not email or not password:
            flash('All fields are required!', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'danger')
            return render_template('register.html')

        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'danger')
            return render_template('register.html')

        # Create new user
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error: {e}")
            db.session.rollback()
            flash('An error occurred during registration.', 'danger')
            return render_template('register.html')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        dish_name = request.form.get('dish_name', '').strip()
        ingredients = request.form.get('ingredients', '').strip()
        description = request.form.get('description', '').strip()

        if not dish_name or not ingredients:
            flash('Dish name and ingredients are required!', 'danger')
            return render_template('create.html')

        # Handle image upload
        image_filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                try:
                    file.save(filepath)
                    image_filename = filename
                except Exception as e:
                    print(f"Error saving image: {e}")
                    flash('Error uploading image. Post created without image.', 'warning')

        new_post = Post(
            dish_name=dish_name,
            ingredients=ingredients,
            description=description if description else None,
            image_filename=image_filename,
            user_id=session['user_id']
        )

        try:
            db.session.add(new_post)
            db.session.commit()
            flash('Your dish has been posted!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            print(f"Error: {e}")
            db.session.rollback()
            flash('An error occurred while creating the post.', 'danger')
            return render_template('create.html')

    return render_template('create.html')


@app.route('/post/<int:id>')
def view_post(id):
    post = Post.query.get_or_404(id)
    return render_template('view_post.html', post=post)


@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update_post(id):
    post = Post.query.get_or_404(id)

    # Check if user owns this post
    if post.user_id != session['user_id']:
        flash('You can only edit your own posts!', 'danger')
        return redirect(url_for('index'))

    if request.method == 'POST':
        post.dish_name = request.form.get('dish_name', '')
        post.ingredients = request.form.get('ingredients', '')
        post.description = request.form.get('description', '')

        # Handle image update
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                post.image_filename = filename

        try:
            db.session.commit()
            flash('Post updated successfully!', 'success')
            return redirect(url_for('view_post', id=post.id))
        except Exception as e:
            print(f"Error: {e}")
            db.session.rollback()
            flash('An error occurred while updating the post.', 'danger')

    return render_template('update.html', post=post)


@app.route('/delete/<int:id>')
@login_required
def delete_post(id):
    post = Post.query.get_or_404(id)

    # Check if user owns this post
    if post.user_id != session['user_id']:
        flash('You can only delete your own posts!', 'danger')
        return redirect(url_for('index'))

    try:
        # Delete image file if exists
        if post.image_filename:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], post.image_filename)
            if os.path.exists(filepath):
                os.remove(filepath)

        db.session.delete(post)
        db.session.commit()
        flash('Post deleted successfully!', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        print(f"Error: {e}")
        flash('An error occurred while deleting the post.', 'danger')
        return redirect(url_for('index'))


@app.route('/profile/<username>')
def profile(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('index'))

    posts = Post.query.filter_by(user_id=user.id).order_by(Post.created.desc()).all()
    return render_template('profile.html', user=user, posts=posts)


if __name__ == '__main__':
    app.run(debug=True)