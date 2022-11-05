import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.sql import func
from flask_login import login_user, logout_user, LoginManager, UserMixin, current_user, login_required


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] ='sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY']='4b8da065572253e8189e51296f5cb26b'


db = SQLAlchemy(app)
login_manager = LoginManager(app)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(255), nullable=False)
    lastname = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.Text(), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f'<User {self.firstname}>'

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime(timezone=True), server_default=func.now())
    comments = db.relationship('Comment', backref='post')

    def __repr__(self):
        return f'<Post "{self.title}">'


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'))

    def __repr__(self):
        return f'<Comment "{self.content[:20]}...">'


@login_manager.user_loader
def user_loader(id):
    return User.query.get(int(id))

@app.route('/')
def index():
    posts = Post.query.all()
    return render_template('index.html', posts=posts)

@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/login_user', methods=['POST'])
def process_login():

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        login_user(user)
        flash('you have succesfully logged in', category='success')
        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/createpost')
def create_post():
   return render_template('post.html')

@app.route('/processpost', methods=['POST'])
@login_required
def process_post():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        user_id = current_user.id

        new_post = Post(title=title, content=content, user_id=user_id )

        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for('index'))

    return render_template('post.html')

@app.route('/signup')
def signup():
    return render_template('register.html')

@app.route('/signup_user', methods=['GET','POST'])
def register():

    if request.method == 'POST':
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        email = request.form.get('email') 
        password = request.form.get('password')     
        confirm = request.form.get('confirm')

                   
        email_exists = User.query.filter_by(email=email).first()
        if email_exists:
            return redirect(url_for('register'))
        
        password_hash = generate_password_hash(password)

        new_user = User(firstname=firstname, lastname=lastname, email=email, password=password_hash)

        db.session.add(new_user)
        db.session.commit()
        flash('you have succesfully created an account', category='success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))



if __name__=='__main__':
    app.run(debug=True)