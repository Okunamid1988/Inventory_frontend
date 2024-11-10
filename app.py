from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://posgres:lamis@localhost/Inventory'
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')

    def __repr__(self):
        return f'<User {self.username}>'

# Route for Home page
@app.route('/')
def home():
    return render_template('index.html')

# Route for SignUp
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another one.', 'danger')
            return redirect(url_for('signup'))

        new_user = User(username=username, password=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()

        flash('SignUp successful! Please login to continue.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

# Route for SignIn
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role

            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))

        flash('Invalid credentials. Please try again.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('login.html')

# Admin Dashboard Route
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    
    return render_template('admin_dashboard.html')

# User Dashboard Route
@app.route('/user_dashboard')
def user_dashboard():
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    
    return render_template('user_dashboard.html')

# Route to Logout
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
