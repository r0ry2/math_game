from flask import Flask, render_template, redirect, url_for, request, flash
from models import db, User
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Question


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'  # غيّرها لاحقًا
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    questions = Question.query.all()
    return render_template('home.html', questions=questions)


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
        return redirect(url_for('admin'))
    return render_template('login.html')


@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied: You are not admin.')
        return redirect(url_for('home'))

    if request.method == 'POST':
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
    return render_template('admin.html', questions=questions)

@app.route('/submit_answer', methods=['POST'])
def submit_answer():
    questions = Question.query.all()
    score = 0
    total = len(questions)

    for question in questions:
        user_answer = request.form.get(f'q{question.id}')
        if user_answer == question.correct_answer:
            score += 1

    return render_template('result.html', score=score, total=total)
@app.route('/delete_question/<int:question_id>')
@login_required
def delete_question(question_id):
    if not current_user.is_admin:
        flash('Access denied.')
        return redirect(url_for('home'))

    question = Question.query.get_or_404(question_id)
    db.session.delete(question)
    db.session.commit()
    flash('تم حذف السؤال بنجاح!')
    return redirect(url_for('admin'))
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
        flash('تم تعديل السؤال بنجاح!')
        return redirect(url_for('admin'))

    return render_template('edit_question.html', question=question)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


# ✅ فقط نسخة واحدة من if __name__ == '__main__':
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin_user = User(
                username='admin',
                password=generate_password_hash('adminpass', method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()

    app.run(debug=True, port=5002)


