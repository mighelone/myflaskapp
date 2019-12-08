from flask import (
    Flask,
    render_template,
    flash,
    redirect,
    url_for,
    session,
    request,
    logging,
)

# from data import Articles
# from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)

# Config SQLalchemy
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class Articles(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    body = db.Column(db.String(1000), nullable=False)
    author = db.Column(db.String(100), nullable=False)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f"{self.name} <{self.username}> - {self.email}"


# Index
@app.route("/")
def index():
    return render_template("home.html")


# About
@app.route("/about")
def about():
    return render_template("about.html")


# Articles
@app.route("/articles")
def articles():
    articles = Articles.query.all()
    if articles:
        return render_template("articles.html", articles=articles)
    else:
        msg = "No Articles Found"
        return render_template("articles.html", msg=msg)


# Single Article
@app.route("/article/<string:id>/")
def article(id):
    article = Articles.query.get(id)
    return render_template("article.html", article=article)


# Register Form Class
class RegisterForm(Form):
    name = StringField("Name", [validators.Length(min=1, max=50)])
    username = StringField("Username", [validators.Length(min=4, max=25)])
    email = StringField("Email", [validators.Length(min=6, max=50)])
    password = PasswordField(
        "Password",
        [
            validators.DataRequired(),
            validators.EqualTo("confirm", message="Passwords do not match"),
        ],
    )
    confirm = PasswordField("Confirm Password")


# User Register
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Create cursor
        new_user = Users(name=name, email=email, username=username, password=password)
        db.session.add(new_user)
        db.session.commit()

        flash("You are now registered and can log in", "success")

        return redirect(url_for("login"))
    return render_template("register.html", form=form)


# User login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Get Form Fields
        username = request.form["username"]
        password_candidate = request.form["password"]

        # Create cursor
        user = Users.query.filter(Users.username == username).first()

        # Get user by username
        # result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if user:
            # Get stored hash
            password = user.password

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session["logged_in"] = True
                session["username"] = username

                flash("You are now logged in", "success")
                return redirect(url_for("dashboard"))
            else:
                error = "Invalid login"
                return render_template("login.html", error=error)
        else:
            error = "Username not found"
            return render_template("login.html", error=error)

    return render_template("login.html")


# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Unauthorized, Please login", "danger")
            return redirect(url_for("login"))

    return wrap


# Logout
@app.route("/logout")
@is_logged_in
def logout():
    session.clear()
    flash("You are now logged out", "success")
    return redirect(url_for("login"))


# Dashboard
@app.route("/dashboard")
@is_logged_in
def dashboard():
    # Create cursor
    articles = Articles.query.filter(Articles.author == session["username"]).all()

    if articles:
        return render_template("dashboard.html", articles=articles)
    else:
        msg = "No Articles Found"
        return render_template("dashboard.html", msg=msg)
    # Close connection


# Article Form Class
class ArticleForm(Form):
    title = StringField("Title", [validators.Length(min=1, max=200)])
    body = TextAreaField("Body", [validators.Length(min=30)])


# Add Article
@app.route("/add_article", methods=["GET", "POST"])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == "POST" and form.validate():
        title = form.title.data
        body = form.body.data

        article = Articles(title=title, body=body, author=session["username"])
        db.session.add(article)
        db.session.commit()

        flash("Article Created", "success")

        return redirect(url_for("dashboard"))

    return render_template("add_article.html", form=form)


# Edit Article
@app.route("/edit_article/<string:id>", methods=["GET", "POST"])
@is_logged_in
def edit_article(id):
    # Get article by id
    article = Articles.query.get(id)

    # Get form
    form = ArticleForm(request.form)

    # Populate article form fields
    form.title.data = article.title
    form.body.data = article.body

    if request.method == "POST" and form.validate():
        article.title = request.form["title"]
        article.body = request.form["body"]
        flash("Article Updated", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit_article.html", form=form)


# Delete Article
@app.route("/delete_article/<string:id>", methods=["POST"])
@is_logged_in
def delete_article(id):
    # Create cursor
    article = Articles.query.get(id)
    db.session.delete(article)
    db.session.commit()
    flash("Article Deleted", "success")

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    app.secret_key = "secret123"
    app.run(debug=True)
