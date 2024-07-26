from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.config['SECRET_KEY'] = 'thisisasecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
app.app_context().push()

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    score = db.Column(db.Integer, default=0)

@app.route("/")
@login_required
def home():
    return render_template('index.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/challenges")
@login_required
def challenges():
    return render_template('challenges.html')

@app.route("/topics")
@login_required
def topics():
    return render_template('topics.html')

@app.route("/backdoor_materials")
@login_required
def backdoor_materials():
    return render_template('backdoor_materials.html')

@app.route("/challenge1")
@login_required
def challenge1():
    return render_template('challenge1.html')


@app.route("/challenge_level1")
@login_required
def challenge_level1():
    return render_template('challenge_level1.html')

@app.route("/backdoor_attack")
@login_required
def backdoor_attack():
    return render_template('backdoor_attack.html')

@app.route("/leaderboard")
@login_required
def leaderboard():
    users = User.query.order_by(User.score.desc()).all()
    return render_template('leaderboard.html', users=users)

@app.route("/models")
@login_required
def models():
    return render_template('models.html')

@app.route("/static/pdf/Rules")
@login_required
def Rules():
    return render_template('Rules.pdf')

@app.route("/getting_started")
@login_required
def getting_started():
    return render_template('getting_started.html')

@app.route('/download/<dataset>/<filename>')
@login_required
def download_file(dataset, filename):
    return send_from_directory(os.path.join('static', 'models', dataset), filename)

@app.route("/submit", methods=['POST'])
@login_required
def submit():
    predictions = {
        'm1': request.form.get('prediction_m1'),
        'm2': request.form.get('prediction_m2'),
        'm3': request.form.get('prediction_m3'),
        'm4': request.form.get('prediction_m4'),
        'm5': request.form.get('prediction_m5'),
        'm6': request.form.get('prediction_m6'),
        # Add all model names and their predictions here up to m32
    }

    actual_labels = {
        "m1": "clean",
        "m2": "backdoored",
        "m3": "clean",
        "m4": "backdoored",
        "m5": "clean",
        "m6": "backdoored",
        # Add all model names and their actual labels here up to m32
    }

    for model, prediction in predictions.items():
        if prediction == actual_labels.get(model, "unknown"):
            current_user.score += 10
        else:
            current_user.score -= 5

    db.session.commit()
    flash('Submission successful!', 'success')
    return redirect(url_for('leaderboard'))

@app.route("/check_db")
def check_db():
    try:
        users = User.query.all()
        return f"Found {len(users)} users in the database."
    except Exception as e:
        return str(e)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)