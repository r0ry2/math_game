from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# ======= Models =======
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    display_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_text = db.Column(db.String(500), nullable=False)
    choice1 = db.Column(db.String(200), nullable=False)
    choice2 = db.Column(db.String(200), nullable=False)
    choice3 = db.Column(db.String(200), nullable=False)
    choice4 = db.Column(db.String(200), nullable=False)
    correct_answer = db.Column(db.String(200), nullable=False)

# ======= Login Loader =======
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ======= Routes =======
@app.route('/')
def home():
    return render_template('home.html')

# ===== Signup =====
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        display_name = request.form.get('display_name')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('signup'))

        new_user = User(
            username=username,
            display_name=display_name,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            is_admin=False
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully. Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')

# ===== Login =====
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))

        login_user(user)
        if user.is_admin:
            return redirect(url_for('admin'))
        else:
            return redirect(url_for('user_questions'))

    return render_template('login.html')

# ===== Logout =====
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# ===== User Questions =====
@app.route('/user_questions', methods=['GET', 'POST'])
@login_required
def user_questions():
    if current_user.is_admin:
        flash('Admins cannot access user questions page.')
        return redirect(url_for('admin'))

    questions = Question.query.all()
    return render_template('user_questions.html', questions=questions, display_name=current_user.display_name)

# ===== Submit Answers =====
@app.route('/submit_answer', methods=['POST'])
@login_required
def submit_answer():
    questions = Question.query.all()
    score = 0
    total = len(questions)
    for question in questions:
        user_answer = request.form.get(f'q{question.id}')
        if user_answer == question.correct_answer:
            score += 1
    return render_template('result.html', score=score, total=total, display_name=current_user.display_name)

# ===== Admin Panel =====
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('home'))

    if request.method == 'POST':
        # إضافة سؤال جديد
        question_text = request.form.get('question_text')
        choice1 = request.form.get('choice1')
        choice2 = request.form.get('choice2')
        choice3 = request.form.get('choice3')
        choice4 = request.form.get('choice4')
        correct_answer = request.form.get('correct_answer')

        new_question = Question(
            question_text=question_text,
            choice1=choice1,
            choice2=choice2,
            choice3=choice3,
            choice4=choice4,
            correct_answer=correct_answer
        )
        db.session.add(new_question)
        db.session.commit()
        flash('Question added successfully!')

    questions = Question.query.all()
    users = User.query.all()
    return render_template('admin.html', questions=questions, users=users)

# ===== Delete Question =====
@app.route('/delete_question/<int:question_id>')
@login_required
def delete_question(question_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('home'))

    question = Question.query.get_or_404(question_id)
    db.session.delete(question)
    db.session.commit()
    flash('Question deleted successfully!')
    return redirect(url_for('admin'))

# ===== Edit Question =====
@app.route('/edit_question/<int:question_id>', methods=['GET', 'POST'])
@login_required
def edit_question(question_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('home'))

    question = Question.query.get_or_404(question_id)
    if request.method == 'POST':
        question.question_text = request.form.get('question_text')
        question.choice1 = request.form.get('choice1')
        question.choice2 = request.form.get('choice2')
        question.choice3 = request.form.get('choice3')
        question.choice4 = request.form.get('choice4')
        question.correct_answer = request.form.get('correct_answer')
        db.session.commit()
        flash('Question updated successfully!')
        return redirect(url_for('admin'))
    return render_template('edit_question.html', question=question)

# ===== Delete User =====
@app.route('/delete_user/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    if user.is_admin:
        flash('Cannot delete admin user.')
        return redirect(url_for('admin'))

    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted successfully!')
    return redirect(url_for('admin'))

# ===== Reset Password =====
@app.route('/reset_password/<int:user_id>', methods=['POST'])
@login_required
def reset_password(user_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    new_password = request.form.get('new_password')
    user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
    db.session.commit()
    flash(f'Password for {user.username} reset successfully!')
    return redirect(url_for('admin'))

# ===== Main =====
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                display_name='Administrator',
                password=generate_password_hash('adminpass', method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()

    app.run(debug=True, port=5000)
