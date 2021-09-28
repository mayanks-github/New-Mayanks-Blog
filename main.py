from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc, Column, Integer, ForeignKey, event, select
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from functools import wraps
from flask import abort
from flask_wtf.csrf import CSRFProtect
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)
csrf = CSRFProtect(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL1", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    blog = relationship("BlogPost", back_populates="user")
    comment = relationship("Comment", back_populates="user")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    user = relationship("User", back_populates="blog")
    comment = relationship("Comment", back_populates="blog")


class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('users.id'))
    user = relationship("User", back_populates="comment")
    blog_id = db.Column(db.Integer, ForeignKey("blog_posts.id"))
    blog = relationship("BlogPost", back_populates="comment")


# db.create_all()

##INITIALIZW GRAVATAR  WITH FLASK
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    get_id = 0
    try:
        if current_user.is_authenticated:
            get_id = current_user.id
    except AttributeError:
        get_id = 0
    return render_template("index.html", all_posts=posts, id=get_id)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        try:
            hash_and_salted_password = generate_password_hash(form.password.data,
                                                              method='pbkdf2:sha256',
                                                              salt_length=8)
            new_user = User(name=form.name.data,
                            email=form.email.data,
                            password=hash_and_salted_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)

            return redirect(url_for('get_all_posts', logged_in=current_user.is_authenticated))
        except exc.IntegrityError:
            flash("You have already signed up with that email, log in instead!")
            return redirect(url_for('login'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = db.session.query(User).filter_by(email=login_form.email.data).first()
        if user:
            if check_password_hash(user.password, login_form.password.data):
                login_user(user)
                flash("You were successfully logged in")
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password is Incorrect')
        else:
            flash('This email does not exist please try with registered email id.')
    print(login_form.errors)
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>/<id>", methods=['GET', 'POST'])
def show_post(post_id, id):
    form = CommentForm()
    all_comment = db.session.query(Comment).filter_by(blog_id=post_id)
    requested_post = BlogPost.query.get(post_id)
    all_users = db.session.query(User)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        new_comment = Comment(text=form.comment.data.split("<")[1].split(">")[1],
                              user_id=current_user.email,
                              blog_id=post_id
                              )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id, id=id, gravatar=gravatar))
    return render_template("post.html", post=requested_post, id=id, comment_form=form, comments=all_comment,
                           users=all_users, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
def add_new_post():
    form = CreatePostForm()
    if request.method == 'POST':
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            date=date.today().strftime("%B %d, %Y"),
            user_id=current_user.email
        )
        db.session.add(new_post)
        db.session.commit()
        print(current_user.id)
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
