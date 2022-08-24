import datetime
from flask import Flask, flash, jsonify, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms.fields import StringField, DateField, SubmitField, SelectField, PasswordField
from wtforms.validators import DataRequired
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
# Connect to Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///to_do.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = "some secret string"
API_KEY = "ranahafez"
db = SQLAlchemy(app)
HASHING_METHOD = 'pbkdf2:sha256'

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    tasks = db.relationship("Task", backref="author")


class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(500), nullable=False)
    date_created = db.Column(db.String(500), nullable=False)
    date_finished = db.Column(db.String(500), nullable=True)
    due_date = db.Column(db.String(500), nullable=True)
    is_done = db.Column(db.Boolean, nullable=False)
    task_author = db.Column("User", db.ForeignKey("users.id"))

    # def to_dict(self):
    #     return {column.name: getattr(self, column.name) for column in self.__table__.columns}


# db.create_all()


class TaskForm(FlaskForm):
    name = StringField('Task Title', validators=[DataRequired()])
    due_date = DateField("Due Date")
    submit = SubmitField(label="Add Task", default=datetime.datetime.today())


class RegisterForm(FlaskForm):
    name = StringField('Your Name', validators=[DataRequired()])
    email = StringField('Your Email', validators=[DataRequired()])
    password = PasswordField('Your Password', validators=[DataRequired()])
    submit = SubmitField(label="Let's Go")


class LoginForm(FlaskForm):
    email = StringField('Your Email', validators=[DataRequired()])
    password = PasswordField('Your Password', validators=[DataRequired()])
    submit = SubmitField(label="Let's Go")


def all_tasks():
    # tasks = db.session.query(Task).all()
    finished = Task.query.filter_by(task_author=current_user.id, is_done=int(True)).all()
    current = Task.query.filter_by(task_author=current_user.id, is_done=int(False)).all()
    return finished, current


@login_required
@app.route("/home", methods=["GET", "POST"])
def main_page():
    if not current_user.is_authenticated:
        flash("You need to login or register to continue.")
        return redirect(url_for("home"))
    task_form = TaskForm()
    if request.method == "POST":
        if task_form.name.data:
            print(task_form.name.data)
            date = task_form.due_date.data.strftime("%d / %m / %Y") if task_form.due_date.data else None
            task = Task(
                name=task_form.name.data,
                date_created=datetime.datetime.now().strftime("%d / %m / %Y"),
                date_finished=None,
                due_date=date,
                is_done=int(False),
                task_author=current_user.id,
            )
            # code to add the task into db
            db.session.add(task)
            db.session.commit()
            # print(task.to_dict())
        else:
            return f"Non Validated {task_form.validate_on_submit()}"
        return redirect(url_for("main_page"))
    return render_template("index.html", form=task_form, to_do=all_tasks()[1], done=all_tasks()[0])


@login_required
@app.route("/delete/<int:id>")
def delete(id):
    task_to_delete = Task.query.get(id)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for("main_page"))


@login_required
@app.route("/done/<int:id>")
def mark_done(id):
    done_task = Task.query.get(id)
    print(done_task)
    done_task.is_done = int(True)
    done_task.date_finished = datetime.datetime.now().strftime("%d / %m / %Y")
    db.session.commit()
    return redirect(url_for("main_page"))


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    print("HEre")
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        # check if it has not account
        print("Here")
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("You do not have an account, Register instead")
            return redirect(url_for("register"))
        # check if the password is not right
        elif not check_password_hash(user.password, password):
            flash("Password Incorrect Try Again Please")
            return redirect(url_for("login"))
        # allow user login
        else:
            # login the user
            login_user(user=user)
            return redirect(url_for("main_page"))
    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # if the user has already an account
        if User.query.filter_by(email=form.email.data).first():
            flash("You have an account try Logging in instead")
            return redirect(url_for("login"))
        hashed_password = generate_password_hash(method= HASHING_METHOD, password=form.password.data, salt_length=8)
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(user=new_user)
        return redirect(url_for('main_page'))
    return render_template("register.html", form=form)


@login_required
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


if __name__ == '__main__':
    app.run(debug=True)
