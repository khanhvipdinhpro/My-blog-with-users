# 1 for flask
# 2 for flask_sqlalchemy
# 3 for flask_wtf
# 4 for flask_login

# 1 import flask module to create a website
from flask import abort, Flask, render_template, redirect, url_for, flash
from datetime import date

# 2 import flask_sqlalchemy module to create database
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
# 4 flask login to track the user
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user, AnonymousUserMixin
from werkzeug.security import generate_password_hash, check_password_hash

# 3 import and flask form to have a bootstrap form
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, CreateNewPostButton
# 3  flask_bootstrap to use bootstrap css and js for flask form
from flask_bootstrap import Bootstrap
# 3  flask_gravatar for random avatar with a specific email
from flask_gravatar import Gravatar
# 3 ckeditor for a content test box
from flask_ckeditor import CKEditor

from functools import wraps
import os

# 1 create an app using flask
app = Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")

# 3 INITIALIZE BOOTSTRAP AND CKEDITOR OBJECT
ckeditor = CKEditor(app)
Bootstrap(app)

# 2 config database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# 2 INITIALIZE SQLALCHEMY OBJECT
db = SQLAlchemy(app)

# 4 INITIALIZE LOGIN OBJECT
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = 'strong'  # login_manager.session_protection = 'basic' causes session to purge
# 3 INITIALIZE GRAVATAR IMG FOR USER AVATAR
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# 4 save user data to use for tracking current user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# 2, 4 Define User class
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    # *******Parent relationship with BlogPost*******#
    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")

    # *******Parent relationship with Comment*******#
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")


# 2 Define BlogPost class
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # *******Child relationship with User*******#
    # Create Foreign Key, "users.id" the users.id refers to the table name of User with column name 'id'
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")

    # ***************Parent Relationship with Comment*************#
    comments = relationship("Comment", back_populates="parent_post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


# 2 Define Comment class
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # Get the text from CKeditor
    text = db.Column(db.Text, nullable=False)

    # *******Child relationship with User*******#
    # "users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comments property in the User class.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship("User", back_populates="comments")

    # ***************Child Relationship with BlogPost*************#
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")


# 2 commit to create a file '.db'
db.create_all()


# 4 make an admin decoration for user with id=1
def admin_only(f):
    # @wraps(f) to ensure not to lose meta-data
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            # Author with specific id and specific post_id so just query author_id and post id if both match then you
            # can delete this post, the same with comment
            try:
                if not BlogPost.query.filter_by(author_id=current_user.id, id=kwargs['post_id']).first():
                    return abort(403)
            except:
                try:
                    if not Comment.query.filter_by(author_id=current_user.id, id=kwargs['comment_id']).first():
                        return abort(403)
                except:
                    return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# 1 2 3 4 = all: define home route
@app.route('/', methods=["POST", "GET"])
def get_all_posts():
    posts = BlogPost.query.all()
    new_post_button = CreateNewPostButton()
    if new_post_button.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to create new post.")
            return redirect(url_for("login"))
        else:
            return redirect(url_for("add_new_post"))
    return render_template("index.html", all_posts=posts, form=new_post_button)


# all: define register route
@app.route('/register', methods=["POST", "GET"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        if User.query.filter_by(email=register_form.email.data).first():
            flash("You've already signed up with that email, log in instead!")
        else:
            # hash password for more security password
            hash_and_salt_password = generate_password_hash(
                register_form.password.data,
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                name=register_form.name.data,
                email=register_form.email.data,
                password=hash_and_salt_password
            )
            db.session.add(new_user)
            db.session.commit()
            # Log in and authenticate user after adding details to database.
            login_user(new_user)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form)


# all: define login route
@app.route('/login', methods=["POST", "GET"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = login_form.email.data
        password = login_form.password.data

        # Find the user by email
        user = db.session.query(User).filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("Your email does not exist. Please try again!")
        else:
            # user.password id password that has been encoded by generate_password_hash() before
            # password is plain password that hasn't been encoded
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password incorrect. Please try again!")
    return render_template("login.html", form=login_form)


# 4 define logout route
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


# all: define post route
@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        # send current user data and requested post to locate who is comment on which post
        new_comment = Comment(
            text=comment_form.comment.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user)


# 1 define about route
@app.route("/about")
def about():
    return render_template("about.html")


# 1 define contact route
@app.route("/contact")
def contact():
    return render_template("contact.html")


# 2 3 define new-post route
@app.route("/new-post", methods=["POST", "GET"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, is_edit=False)


# 2 3 define edit-post route also use make-post template only change the heading in html file
@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True)


# 3 define delete post route
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


# 3 define delete-comment route
@app.route("/delete-comment/<int:comment_id>")
@admin_only
def delete_comment(comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    post_id = comment_to_delete.post_id
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


if __name__ == "__main__":
    app.run(debug=True)
