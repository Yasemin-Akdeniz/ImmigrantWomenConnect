from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime

# Initialize the Flask application
app = Flask(__name__)

# Application configuration
# IMPORTANT: Change this to a strong, random key! Example: os.urandom(24).hex()
app.config['SECRET_KEY'] = 'lalala'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy database object
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- OOP Practice: User Class ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

# --- OOP Practice: Resource Class ---
class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    link = db.Column(db.String(200), nullable=True)
    category = db.Column(db.String(50), nullable=False)
    posted_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    author = db.relationship('User', backref='resources', lazy=True)

    def __repr__(self):
        return f"Resource('{self.title}', '{self.date_posted}')"

# Flask-Login user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Database Creation ---
# This block creates the database tables based on defined models (like User and Resource).
# IMPORTANT: Run it only ONCE when you first set up the database, or when you add a new model.
# To run:
# 1. UNCOMMENT the 'with app.app_context():' block below.
# 2. Delete your 'site.db' file from your project folder.
# 3. Run 'python app.py' in your terminal.
# 4. Once 'site.db' is created and you see "Database created or updated." message,
#    COMMENT OUT this entire block again to prevent data loss or unnecessary re-creation on every app restart.
# with app.app_context():
#     db.create_all()
#     print("Database created or updated.")


# --- Routes (Pages) ---
@app.route('/')
def home():
    # Fetch latest 3 resources for display on homepage
    latest_resources = Resource.query.order_by(Resource.date_posted.desc()).limit(3).all()
    return render_template('index.html', latest_resources=latest_resources)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('register'))

        user_exists = User.query.filter_by(username=username).first()
        email_exists = User.query.filter_by(email=email).first()

        if user_exists:
            flash('Username already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        if email_exists:
            flash('Email address already registered. Please use a different email or login.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_template('auth/login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/add_resource', methods=['GET', 'POST'])
@login_required
def add_resource():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        link = request.form.get('link')
        category = request.form.get('category')

        if not title or not description or not category:
            flash('Title, Description, and Category are required.', 'danger')
            return redirect(url_for('add_resource'))

        new_resource = Resource(
            title=title,
            description=description,
            link=link if link else None,
            category=category,
            posted_by_id=current_user.id
        )
        db.session.add(new_resource)
        db.session.commit()

        flash('Resource added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_resource.html')

@app.route('/resources')
def list_resources():
    search_query = request.args.get('search', '') # Get search query from URL, default to empty string
    category_filter = request.args.get('category', '') # Get category filter from URL

    # Start with all resources ordered by date
    resources = Resource.query.order_by(Resource.date_posted.desc())

    # Apply search filter if query exists
    if search_query:
        resources = resources.filter(
            (Resource.title.ilike(f'%{search_query}%')) | # Case-insensitive title search
            (Resource.description.ilike(f'%{search_query}%')) # Case-insensitive description search
        )

    # Apply category filter if category is selected
    if category_filter and category_filter != 'All': # 'All' option will show all categories
        resources = resources.filter_by(category=category_filter)

    all_resources = resources.all() # Execute the query

    # Get unique categories for the filter dropdown
    # This queries distinct categories from the database, converts to a list, and sorts them
    unique_categories = sorted(list(set([res.category for res in Resource.query.all()])))
    unique_categories.insert(0, 'All') # Add 'All' option at the beginning

    return render_template('resources.html',
                           resources=all_resources,
                           search_query=search_query,
                           category_filter=category_filter,
                           unique_categories=unique_categories)


if __name__ == '__main__':
    app.run(debug=True)
