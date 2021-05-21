from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email
from typing import Callable
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL1",  "sqlite:///lists.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


class MySQLAlchemy(SQLAlchemy):
    Column: Callable
    Integer: Callable
    String: Callable
    Text: Callable
    ForeignKey: Callable
    Boolean: Callable


db = MySQLAlchemy(app)
Base = declarative_base()


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    lists = relationship("ToDoList", back_populates="list_creator")
    tasks = relationship("Task", back_populates="task_creator")


class ToDoList(db.Model):
    __tablename__ = "to_do_lists"
    id = db.Column(db.Integer, primary_key=True)

    list_name = db.Column(db.String(250), nullable=False)

    done = db.Column(db.Boolean, unique=False, default=False)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    list_creator = relationship("User", back_populates="lists")

    tasks = relationship("Task", back_populates="parent_list")


class Task(db.Model):
    __tablename__ = "posted_tasks"
    id = db.Column(db.Integer, primary_key=True)

    task_name = db.Column(db.String(250), nullable=False)

    done = db.Column(db.Boolean, unique=False, default=False)

    creator_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    task_creator = relationship("User", back_populates="tasks")
    list_id = db.Column(db.Integer, db.ForeignKey("to_do_lists.id"))
    parent_list = relationship("ToDoList", back_populates="tasks")


class EntryForm(FlaskForm):
    entry = StringField("New To-Do List", validators=[DataRequired()])
    submit = SubmitField("Add")


class EditNameForm(FlaskForm):
    entry = StringField("To-Do List Name", validators=[DataRequired()])
    submit = SubmitField("Update")


class TasksEntryForm(FlaskForm):
    entry = StringField("New Task", validators=[DataRequired()])
    submit = SubmitField("Add")


class EditTasksForm(FlaskForm):
    entry = StringField("Task Name", validators=[DataRequired()])
    submit = SubmitField("Update")


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")


db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first())
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_lists"))

    return render_template("register.html", form=form, current_user=current_user)


@app.route('/', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_lists'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/all-lists")
def get_all_lists():
    if not current_user.is_authenticated:
        flash("You need to login or register to comment.")
        return redirect(url_for("login"))
    lists = User.query.get(current_user.id).lists
    return render_template("all-lists.html", all_lists=lists, current_user=current_user)


@app.route("/new-list", methods=["GET", "POST"])
def add_new_list():
    if not current_user.is_authenticated:
        flash("You need to login or register to comment.")
        return redirect(url_for("login"))
    form = EntryForm()
    if form.validate_on_submit():
        new_list = ToDoList(
            list_name=form.entry.data,
            list_creator=current_user
        )
        db.session.add(new_list)
        db.session.commit()

        return redirect(url_for("add_new_task", list_id=current_user.lists.index(new_list)))

    return render_template("new-list.html", current_user=current_user, form=form)


@app.route("/create-task/<int:list_id>", methods=["GET", "POST"])
def add_new_task(list_id):
    if not current_user.is_authenticated:
        flash("You need to login or register to comment.")
        return redirect(url_for("login"))
    to_do_list = User.query.get(current_user.id).lists[list_id]
    form = TasksEntryForm()
    if form.validate_on_submit():
        new_task = Task(
            task_name=form.entry.data,
            task_creator=current_user,
            parent_list=to_do_list
        )
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for("add_new_task", list_id=list_id))

    return render_template("create-task.html", current_user=current_user, form=form, list_id=list_id)


@app.route("/tasks/<int:list_id>", methods=["GET", "POST"])
def show_tasks(list_id):
    requested_list = User.query.get(current_user.id).lists[list_id]
    if not current_user.is_authenticated:
        flash("You need to login or register to comment.")
        return redirect(url_for("login"))

    return render_template("show-tasks.html", list=requested_list, current_user=current_user, list_id=list_id)


@app.route("/edit-tasks/<int:list_id>", methods=["GET", "POST"])
def edit_tasks(list_id):
    requested_list = User.query.get(current_user.id).lists[list_id]
    if not current_user.is_authenticated:
        flash("You need to login or register to comment.")
        return redirect(url_for("login"))

    return render_template(
        "show-tasks.html", list=requested_list, current_user=current_user, list_id=list_id, is_edit=True)


@app.route("/edit-lists", methods=["GET", "POST"])
def edit_lists():
    if not current_user.is_authenticated:
        flash("You need to login or register to comment.")
        return redirect(url_for("login"))

    lists = User.query.get(current_user.id).lists
    return render_template(
        "all-lists.html", all_lists=lists, current_user=current_user, is_edit=True)


@app.route("/edit/<int:list_id>/<int:task_id>", methods=["GET", "POST"])
def edit_task(list_id, task_id):
    requested_list = User.query.get(current_user.id).lists[list_id]
    if not current_user.is_authenticated:
        flash("You need to login or register to comment.")
        return redirect(url_for("login"))

    edit_tasks_form = EditTasksForm(entry=requested_list.tasks[task_id].task_name)
    if edit_tasks_form.validate_on_submit():
        requested_list.tasks[task_id].task_name = edit_tasks_form.entry.data
        db.session.commit()

        return redirect(url_for("edit_tasks", list_id=list_id))

    return render_template(
        "edit-list.html", list_id=list_id, task_id=task_id, form=edit_tasks_form, current_user=current_user)


@app.route("/edit-list/<int:list_id>", methods=["GET", "POST"])
def edit_list(list_id):
    requested_list = User.query.get(current_user.id).lists[list_id]
    if not current_user.is_authenticated:
        flash("You need to login or register to comment.")
        return redirect(url_for("login"))

    edit_list_form = EditNameForm(entry=requested_list.list_name)
    if edit_list_form.validate_on_submit():
        requested_list.list_name = edit_list_form.entry.data

        db.session.commit()
        lists = User.query.get(current_user.id).lists
        return redirect(url_for("edit_lists", all_lists=lists))

    return render_template(
        "edit-list.html", current_user=current_user, form=edit_list_form, list_id=list_id, is_list=True)


@login_required
@app.route("/delete-task/<int:task_id>/<int:list_id>")
def delete_task(task_id, list_id):
    task_to_delete = Task.query.get(task_id + 1)
    db.session.delete(task_to_delete)
    db.session.commit()
    return redirect(url_for("edit_tasks", list_id=list_id))


@login_required
@app.route("/delete-list/<int:list_id>")
def delete_list(list_id):
    list_to_delete = ToDoList.query.get(list_id + 1)
    db.session.delete(list_to_delete)
    db.session.commit()
    return redirect(url_for("edit_lists", list_id=list_id))


@login_required
@app.route("/done-task/<int:task_id>/<int:list_id>")
def done_task(task_id, list_id):
    task_done = Task.query.get(task_id + 1)
    if task_done.done is False:
        task_done.done = True
    elif task_done.done is True:
        task_done.done = False
    db.session.commit()
    return redirect(url_for("show_tasks", list_id=list_id))


@login_required
@app.route("/done-list/<int:list_id>")
def done_list(list_id):
    list_done = ToDoList.query.get(list_id + 1)
    if list_done.done is False:
        list_done.done = True
    elif list_done.done is True:
        list_done.done = False
    db.session.commit()
    return redirect(url_for("get_all_lists"))


if __name__ == "__main__":
    app.run(host="localhost", port=5000)
