from flask import Flask, render_template, url_for,  flash, redirect, request, session, make_response
from flask_wtf.file import FileField, FileAllowed
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, ValidationError, EqualTo, Email
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from PIL import Image
import re
import secrets
import os
from flask import Flask, redirect, url_for
import time
import requests
import json
import pandas as pd
import folium
import urllib.parse
from requests_oauthlib import OAuth1
import tweepy

app = Flask(__name__)

# this is the serects numbers
app.config['SECRET_KEY'] = 'ea7b11f0714027a81e7f81404612d80d'

# how to add the
# DB_URL = 'postgresql+psycopg2://jasonjia:227006636@csce-315-db.engr.tamu.edu/SILT_DB'.format(user=POSTGRES_USER,pw=POSTGRES_PW,url=POSTGRES_URL,db=POSTGRES_DB)
# DB_URL1 = 'postgresql://jasonjia:227006636@csce-315-db.engr.tamu.edu:5432/SILT_DB_test'
DB_URL1 = 'postgresql://doadmin:jglyvd028l8ced6h@db-silt-db-do-user-8284135-0.b.db.ondigitalocean.com:25060/defaultdb'
app.config['SQLALCHEMY_DATABASE_URI']=DB_URL1
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # silence the deprecation warning

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
# bootstrap color
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
     return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(180), unique = True, nullable = False)
    twitter_username = db.Column(db.String(50), unique=True, default = None)
    username = db.Column(db.String(30), unique = True, nullable = False)
    password = db.Column(db.String(), nullable = False)
    user_pic = db.Column(db.String(20), nullable = False, default='default.jpg')
    posts = db.relationship('Post', backref='author', lazy = True)
    posts_ac = db.relationship('Post_ac', backref='author', lazy = True)
    post_h = db.relationship('Post_h', backref='author', lazy = True)
    post_sp = db.relationship('Post_sp', backref='author', lazy = True)
    post_cr = db.relationship('Post_cr', backref='author', lazy = True)
    post_ev = db.relationship('Post_ev', backref='author', lazy = True)
    spotifyartist = db.relationship('SpotifyArtist', backref='author', lazy = True)

    def __init__(self, email, username, password):
        self.email = email
        self.username = username
        self.password = password

    def __repr__ (self):
        return f"User('{self.username}', '{self.email}', '{self.user_pic}', '{self.id}')"


class Post(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50), nullable = False)
    post_time = db.Column(db.DateTime, nullable = False, default=datetime.utcnow)
    content = db.Column(db.String, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.tile}', '{self.post_time}', '{self.content}')"


class Post_ac(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50), nullable = False)
    post_time = db.Column(db.DateTime, nullable = False, default=datetime.utcnow)
    content = db.Column(db.String, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.tile}', '{self.post_time}', '{self.content}')"


class Post_h(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50), nullable = False)
    post_time = db.Column(db.DateTime, nullable = False, default=datetime.utcnow)
    content = db.Column(db.String, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.tile}', '{self.post_time}', '{self.content}')"

class Post_sp(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50), nullable = False)
    post_time = db.Column(db.DateTime, nullable = False, default=datetime.utcnow)
    content = db.Column(db.String, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.tile}', '{self.post_time}', '{self.content}')"


class Post_cr(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50), nullable = False)
    post_time = db.Column(db.DateTime, nullable = False, default=datetime.utcnow)
    content = db.Column(db.String, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.tile}', '{self.post_time}', '{self.content}')"



class Post_ev(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(50), nullable = False)
    post_time = db.Column(db.DateTime, nullable = False, default=datetime.utcnow)
    content = db.Column(db.String, nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Post('{self.tile}', '{self.post_time}', '{self.content}')"





class SpotifyArtist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    artist_name = db.Column(db.String(2000), nullable=False)
    artist_id = db.Column(db.String(2000), nullable=False)
    # time_range = db.Column(db.String(15), nullable=False)

    def __repr__(self):
        return f"SpotifyArtist('{self.artist_name}', '{self.artist_id}')"


# do not change this
# from form import account, LoginForm, update_account, PostForm, spotify_profile

####################
##  FORMS         ##
####################

class account(FlaskForm):
    # user name not null and not too long. Add validation
    username = StringField('Username', validators=[DataRequired(), Length(min = 2, max = 30)])
    email = StringField('Email', validators=[DataRequired(), Length(min = 6), Email()])

    password = PasswordField('Password', validators=[DataRequired()])
    confirmed_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    # def tamu_email_validate(self, form, field):
    #     # [A-Za-z0-9] firt character to match it.
    #     if not re.search(r"^[A-Za-z0-9](\.?[a-z0-9]){5,}@tamu\.edu$", field.data):
    #         raise ValidationError("Invalid Email Address")
    #     return True
    # def validate_email(self, email):
    #     # [A-Za-z0-9] firt character to match it.
    #     if not re.search(r"^[A-Za-z0-9](\.?[a-z0-9]){5,}@tamu\.edu$", field.data):
    #         raise ValidationError("Invalid Email Address")
    #     # return True
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is taken, Please choose a new one')

    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('Email is taken, Please choose a new one')
        # if not re.search(r"^[A-Za-z0-9](\.?[a-z0-9]){5,}@tamu\.edu$", email):
        #     raise ValidationError("Invalid Email Address")




class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(min = 6)])
    password = PasswordField('Password', validators=[DataRequired()])
    remeber = BooleanField('Remember Me')
    submit = SubmitField('Login')



class update_account(FlaskForm):
    # user name not null and not too long. Add validation
    username = StringField('Username', validators=[DataRequired(), Length(min = 2, max = 30)])
    email = StringField('Email', validators=[DataRequired(), Length(min = 6), Email()])
    picture = FileField('Update Your Picture', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Update')
    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username is taken, Please choose a new one')

    def validate_email(self, email):
        if email.data != current_user.email:
            email = User.query.filter_by(email=email.data).first()
            if email:
                raise ValidationError('Email is taken, Please choose a new one')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')
    tweet = BooleanField('Post On Twitter')

class spotify_profile(FlaskForm):
    artist_name = StringField('Artist', validators=[DataRequired()])
    artist_id = StringField('Artist_ID', validators=[DataRequired()])
    # time_range = StringField('time_range')

########################
##   END FORMS        ##
########################


@app.route("/", methods=['GET', 'POST'])
@app.route("/home", methods=['GET', 'POST'])
# in terminal:
# debug mode in flask:  export FLASK_DEBUG=1
# run flask: flask run
def home():
    posts = Post.query.all()
    return render_template("home.html", posts=posts)


# @app.route("/funny")
# def funny():
#     return render_template("funny.html")
#
#
@app.route("/Events", methods=['GET', 'POST'])
def eve():
    posts_ev = Post_ev.query.all()
    return render_template("Events.html", posts=posts_ev)

@app.route("/funny", methods=['GET', 'POST'])
def fun():
    posts_h = Post_h.query.all()
    return render_template("funny.html", posts= posts_h)

@app.route("/studyLounge", methods=['GET', 'POST'])
def study_lounge():
    posts_ac = Post_ac.query.all()
    return render_template("studylounge.html", posts = posts_ac)

@app.route("/sports", methods=['GET', 'POST'])
def sports():
    posts_sp = Post_sp.query.all()
    return render_template("sports.html", posts = posts_sp)

@app.route("/course", methods=['GET', 'POST'])
def course():
    posts_cr = Post_cr.query.all()
    return render_template("course.html", posts = posts_cr)


@app.route('/profile/<username>')
def user_profile(username):

    # data we query
    # dbArtists = SpotifyArtist.query.filter_by(user_id = current_user.id).first()


    data = User.query.filter_by(username = username).first()
    spotify_data = SpotifyArtist.query.filter_by(user_id = data.id).first()
    print (spotify_data)
    # print ((data))

    artistArr = []
    if (spotify_data != None):
        if (len(spotify_data.artist_name.split(',! ')) == 31):
            artistArr = spotify_data.artist_name.split(',! ')[20:-1]
            print(artistArr)
    # return render_template("user_profile.html", posts=data, art = spotify_data)
    return render_template("user_profile.html", posts=data, art=artistArr, len=len(artistArr))


    return str(username)



@app.route("/resources")
def resources():
    return render_template("resources.html")

def save_image(form_picture):
    random_h = secrets.token_hex(8)
    _, fext = os.path.splitext(form_picture.filename)
    picture_fn = random_h + fext
    # root path attrinbute
    picture_path = os.path.join(app.root_path, 'static/image', picture_fn)
    output_size = (125,125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn


@app.route("/profile", methods = ['GET', 'POST'])
@login_required
def profile(artists=[], artist_ids=[]):

    time_range = ['short_term', 'medium_term', 'long_term']
    leng = 0

    print(artists)

    if (len(artists) != 0):
        # going to be 3
        artists_string = ""
        artists_id_string = ""
        time_range_string = ""
        for i in range(len(artists)):
            for j in range(len(artists[0])):
                # artists[i][j], artist_ids[i][j]
                artists_string+=artists[i][j]
                artists_string+=",! "
                artists_id_string+=artist_ids[i][j]
                artists_id_string+=", "

        print(artists_string)
        print(artists_id_string)
        spo = SpotifyArtist(artist_name = artists_string, artist_id = artists_id_string, author=current_user)
        db.session.add(spo)
        db.session.commit()

    # how can we save it to a online drive???
    #image_file = 'https://i.pinimg.com/originals/0c/3b/3a/0c3b3adb1a7530892e55ef36d3be6cb8.png'
    form = update_account()
    if form.validate_on_submit():
        if form.picture.data:
            pic_file = save_image(form.picture.data)
            current_user.user_pic = pic_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('You account is updated! ', 'success')
        return redirect(url_for('profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename = 'image/' + current_user.user_pic, width=100)

    dbArtists = SpotifyArtist.query.filter_by(user_id = current_user.id).first()
    print("dbArtists:", dbArtists)
    # return render_template("home.html", posts=posts)

    artistArr = []
    if (dbArtists != None):
        if (len(dbArtists.artist_name.split(',! ')) == 31):
            artistArr = dbArtists.artist_name.split(',! ')[20:-1]
            print(artistArr)

    return render_template("profile.html", title='Profile', image_file = image_file, form = form, leng=len(artistArr), posts=artistArr)


@app.route("/register", methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = account()
    if form.validate_on_submit():
        # hash the paswword to save to our database
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        # create a new user
        user= User(username = form.username.data, email = form.email.data, password = hashed_password)
        db.session.add(user)
        db.session.commit()

        flash(f'Account created! You can now log in! ','success')
    # we also need to redirect user to home page
        return redirect(url_for('login'))
    return render_template('register.html', title = 'Register', form = form)


@app.route("/login", methods = ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember = form.remeber.data)
            next_page = request.args.get('next')
            # special python return
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login not successful. Please check your password and email.', 'danger')
    return render_template('login.html', title = 'Login', form = form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

gloabal_true = False
@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    #  and form.tweet.data == True
    if gloabal_true == True:

        twitter_consumer_key = "bw5c7K2tzsceOlgenVFDRnogU"
        twitter_consumer_secret = "CTXbMs9vFwFCdYrM2CGkVsSsLl53LpO43FNeAwTcX5zukDg36m"
        token_url = 'https://api.twitter.com/1.1/statuses/update.json'
        token_secret = (session["twitter_secret"])
        access_token = (session["twitter_token"])
        print ("Auth: ")
        print(access_token, token_secret)
        if form.tweet.data == True:
            print ("it is true")

            auth = tweepy.OAuthHandler(twitter_consumer_key, twitter_consumer_secret)
            auth.set_access_token(access_token, token_secret)
            # Create API object
            api = tweepy.API(auth)
            # Create a tweet
            api.update_status(form.content.data)
            # post_response = requests.post(resource_url, auth=tw, data=body)
            # post_response = requests.post(request_url, auth = tw)
            # body = {'code': code, 'redirect_uri': redirect_uri, 'grant_type': 'authorization_code', 'client_id': CLI_ID, 'client_secret': CLI_SEC}


    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title = 'Forum', form = form)


@app.route("/post/new/ac", methods=['GET', 'POST'])
@login_required
def new_post_ac():
    form = PostForm()
    #  and form.tweet.data == True
    if form.tweet == True:
        flash("make a tweet",'success')
    if form.validate_on_submit():
        post = Post_ac(title=form.title.data, content=form.content.data, author=current_user)
        print (request.form.get('mycheckbox'))
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title = 'Forum', form = form)

@app.route("/post/new/h", methods=['GET', 'POST'])
@login_required
def new_post_h():
    form = PostForm()
    #  and form.tweet.data == True
    if form.tweet == True:
        flash("make a tweet",'success')
    if form.validate_on_submit():
        post = Post_h(title=form.title.data, content=form.content.data, author=current_user)
        print (request.form.get('mycheckbox'))
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title = 'Forum', form = form)



@app.route("/post/new/sp", methods=['GET', 'POST'])
@login_required
def new_post_sp():
    form = PostForm()
    #  and form.tweet.data == True
    if form.tweet == True:
        flash("make a tweet",'success')
    if form.validate_on_submit():
        post = Post_sp(title=form.title.data, content=form.content.data, author=current_user)
        print (request.form.get('mycheckbox'))
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title = 'Forum', form = form)

@app.route("/post/new/ev", methods=['GET', 'POST'])
@login_required
def new_post_ev():
    form = PostForm()
    #  and form.tweet.data == True
    if form.tweet == True:
        flash("make a tweet",'success')
    if form.validate_on_submit():
        post = Post_ev(title=form.title.data, content=form.content.data, author=current_user)
        print (request.form.get('mycheckbox'))
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title = 'Forum', form = form)



@app.route("/post/new/cr", methods=['GET', 'POST'])
@login_required
def new_post_cr():
    form = PostForm()
    #  and form.tweet.data == True
    if form.tweet == True:
        flash("make a tweet",'success')
    if form.validate_on_submit():
        post = Post_cr(title=form.title.data, content=form.content.data, author=current_user)
        print (request.form.get('mycheckbox'))
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title = 'Forum', form = form)

# oauth = OAuth(app)
#
# twitter = oauth.remote_app('twitter',
#                             consumer_key = 'bw5c7K2tzsceOlgenVFDRnogU',
#                             consumer_secret='CTXbMs9vFwFCdYrM2CGkVsSsLl53LpO43FNeAwTcX5zukDg36m',
#                             base_url='https://api.twitter.com/1.1/',
#                             request_token_url='https://api.twitter.com/oauth/request_token',
#                             access_token_url='https://api.twitter.com/oauth/access_toke',
#                             authorize_url='https://api.twitter.com/oauth/authorize'
# )



# DELETE this






@app.route('/twitter_login')
def twitterPostForRequestToken():
    request_url = 'https://api.twitter.com/oauth/request_token'
	# authorization = app.config['AUTHORIZATION']
    twitter_redirect_url = "http%3A%2F%2Fsilt-tamu.herokuapp.com%2Ftwitter_callback"
    # oauth_callback="http%3A%2F%2Fmyapp.com%3A3005%2Ftwitter%2Fprocess_callback"

	# headers = {'Authorization': authorization, 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
    #headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
    twitter_consumer_key = "bw5c7K2tzsceOlgenVFDRnogU"
    twitter_consumer_secret = "CTXbMs9vFwFCdYrM2CGkVsSsLl53LpO43FNeAwTcX5zukDg36m"
    tw = OAuth1(twitter_consumer_key, twitter_consumer_secret)
    headers = {'oauth_callback': twitter_redirect_url, 'oauth_consumer_key': twitter_consumer_key}
    #body = {'code': code, 'redirect_uri': redirect_uri, 'grant_type': 'authorization_code', 'client_id': CLI_ID, 'client_secret': CLI_SEC}

    post_response = requests.post(request_url, auth = tw)
    # print("Twitter Post Response:")

    attrs = vars(post_response)
    twitter_oauth = attrs.get('_content')

    oauth_arr = str(twitter_oauth)[2:].split('&')
    # oauth_token = oauth_arr[0].split('=')[1]
    # oauth_token_secret = oauth_arr[1].split('=')[1]
    oauth_token = oauth_arr[0]
    oauth_token_secret = oauth_arr[1]
    # print (oauth_token)
    # print (oauth_token_secret)
    authorize_url = "https://api.twitter.com/oauth/authorize?" + oauth_token
    return redirect(authorize_url)


    # 200 code indicates access token was properly granted
    # if post_response.status_code == 200:
    #     json = post_response.json()
    #     return json['access_token'], json['refresh_token'], json['expires_in']
    # else:
    #     print("LOGGING: " + 'getToken:' + str(post_response.status_code))
    #     # logging.error('getToken:' + str(post_response.status_code))
    #     return None

# https://yourCallbackUrl.com?oauth_token=NPcudxy0yU5T3tBzho7iCotZ3cnetKwcTIRlX0iwRl0&oauth_verifier=uw7NjWHT6OJ1MpJOXsHfNxoAhPKpgI8BlYDhxEjIBY
@app.route('/twitter_callback')
def twitter_callback():
    url_parse = request.url
    parse_arr = url_parse.split('=')[1:]
    token = parse_arr[0].split('&')[0]
    verifier = parse_arr[1]
    # print (token, verifier)

    request_url = 'https://api.twitter.com/oauth/access_token'
	# authorization = app.config['AUTHORIZATION']
    # twitter_redirect_url = "http%3A%2F%2F127.0.0.1%3A5000%2Ftwitter_callback"
    # oauth_callback="http%3A%2F%2Fmyapp.com%3A3005%2Ftwitter%2Fprocess_callback"

	# headers = {'Authorization': authorization, 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
    #headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
    twitter_consumer_key = "bw5c7K2tzsceOlgenVFDRnogU"
    twitter_consumer_secret = "CTXbMs9vFwFCdYrM2CGkVsSsLl53LpO43FNeAwTcX5zukDg36m"

    # oauth = OAuth1(client_key,
    #                client_secret=client_secret,
    #                resource_owner_key=resource_owner_key,
    #                resource_owner_secret=resource_owner_secret,
    #                verifier=verifier)

    tw = OAuth1(twitter_consumer_key, client_secret=twitter_consumer_secret, resource_owner_key=token, verifier=verifier)
    post_response = requests.post(request_url, auth = tw)
    attrs = vars(post_response)
    # print (attrs)
    twitter_oauth = attrs.get('_content')
    # print ("Content: ")
    # print (twitter_oauth)
    oauth_arr = str(twitter_oauth)[2:].split('&')
    # oauth_token = oauth_arr[0].split('=')[1]
    # oauth_token_secret = oauth_arr[1].split('=')[1]
    oauth_token = oauth_arr[0].split('=')[1]
    oauth_token_secret = oauth_arr[1].split('=')[1]

    print (oauth_token, oauth_token_secret)

    print("tokens:")
    print(oauth_token, oauth_token_secret)

    session.pop('twitter_token', None) # delete visits
    session.pop('twitter_secret', None) # delete visits
    session['twitter_token'] = oauth_token
    session['twitter_secret'] = oauth_token_secret
    session.modified = True
    # posts = {"status": "test tweet"}
    # token_url = 'https://api.twitter.com/1.1/statuses/update.json'
    # tw = OAuth1(twitter_consumer_key,
    #             resource_owner_key=oauth_token,
    #             resource_owner_secret=oauth_token_secret,
    #             client_secret=twitter_consumer_secret)
    # a = requests.post(token_url, data=posts, auth = tw)
    # print (vars(a))
    #
    # auth = tweepy.OAuthHandler(twitter_consumer_key, twitter_consumer_secret)
    # auth.set_access_token(oauth_token, oauth_token_secret)
    # # Create API object
    # api = tweepy.API(auth)
    # # Create a tweet
    # api.update_status("Hello Tweepy2")
    return redirect('/')


##############################
#       Spotify section
##############################

# Spotify Prerequirements
CLI_ID = "035c861c44084c46bf08f93efed2bb4c"
CLI_SEC = "18cba64539fc4c39894f8b17b4e78b6e"
API_BASE = 'https://accounts.spotify.com'
REDIRECT_URI = "http://silt-tamu.herokuapp.com/api_callback"
SCOPE = 'playlist-modify-private,playlist-modify-public,user-top-read, user-library-read'

# Set this to True for testing but you probaly want it set to False in production.
SHOW_DIALOG = True
# Spotify pre-requirements end

@app.route("/spotify_authorize")
def authorize():
    client_id = CLI_ID
    redirect_uri = REDIRECT_URI
    # TODO: change scope value
    scope = SCOPE

    # state_key = createStateKey(15)
    # session['state_key'] = state_key

    authorize_url = 'https://accounts.spotify.com/en/authorize?'
    # parameters = 'response_type=code&client_id=' + client_id + '&redirect_uri=' + redirect_uri + '&scope=' + scope + '&state=' + state_key
    parameters = 'response_type=code&client_id=' + client_id + '&redirect_uri=' + redirect_uri + '&scope=' + scope
    response = make_response(redirect(authorize_url + parameters))
    print("response")
    return response


"""
Called after a new user has authorized the application through the Spotift API page.
Stores user information in a session and redirects user back to the page they initally
attempted to visit.
"""
@app.route('/api_callback')
def callback():
    # make sure the response came from Spotify
    # if request.args.get('state') != session['state_key']:
    # 	# return render_template('index.html', error='State failed.')
    #     print("Error: State Failed")
        # return
    if request.args.get('error'):
    	# return render_template('index.html', error='Spotify error.')
        print("Error: Spotify error")

    else:
        code = request.args.get('code')
        # session.pop('state_key', None)
    	# get access token to make requests on behalf of the user
        payload = getToken(code)
        if payload != None:
            session['token'] = payload[0]
            session['refresh_token'] = payload[1]
            session['token_expiration'] = time.time() + payload[2]
        else:
            # return render_template('index.html', error='Failed to access token.')
            return "Failed to access token"

    current_user = getUserInformation(session)
    print("CURRENT USER:", current_user)

    session['user_id'] = current_user['id']
    # logging.info('new user:' + session['user_id'])
    print("LOGGING: " + 'new user:' + session['user_id'])

    # track_ids = getAllTopTracks(session)
    artist_names, artist_ids = getAllTopArtists(session)

    # if form.validate_on_submit() and form.tweet.data == True:
    #     post = Post(title=form.title.data, content=form.content.data, author=current_user)
    #     db.session.add(post)
    #     db.session.commit()
    #     flash('Your post has been created', 'success')
    #     return redirect(url_for('home'))



    # print("------------------Artists---------------------")
    time_range = ['short_term', 'medium_term', 'long_term']

    # for i in range(len(artist_names)):
    #     term = time_range[i]
    #
    #     for j in range(len(artist_names[0])):
    #         print(artist_names[i][j], artist_ids[i][j])
    #         SpotifyArtist = SpotifyArtist(user_id= , artist_name=artist_names[i][j], artist_id=artist_ids[i][j], time_range=term)

    print("\nright before printing track_ids")
    return profile(artists=artist_names, artist_ids=artist_ids)


def getToken(code):
    token_url = 'https://accounts.spotify.com/api/token'
	# authorization = app.config['AUTHORIZATION']
    redirect_uri = REDIRECT_URI

	# headers = {'Authorization': authorization, 'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
    headers = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
    body = {'code': code, 'redirect_uri': redirect_uri, 'grant_type': 'authorization_code', 'client_id': CLI_ID, 'client_secret': CLI_SEC}
    post_response = requests.post(token_url, headers=headers, data=body)

    # 200 code indicates access token was properly granted
    if post_response.status_code == 200:
        json = post_response.json()
        return json['access_token'], json['refresh_token'], json['expires_in']
    else:
        print("LOGGING: " + 'getToken:' + str(post_response.status_code))
        # logging.error('getToken:' + str(post_response.status_code))
        return None


"""
Makes a GET request with the proper headers. If the request succeeds, the json parsed
response is returned. If the request fails because the access token has expired, the
check token function is called to update the access token.
Returns: Parsed json response if request succeeds or None if request fails
"""
def makeGetRequest(session, url, params={}):
	headers = {"Authorization": "Bearer {}".format(session['token'])}
	response = requests.get(url, headers=headers, params=params)

	# 200 code indicates request was successful
	if response.status_code == 200:
		return response.json()

	# if a 401 error occurs, update the access token
	elif response.status_code == 401 and checkTokenStatus(session) != None:
		return makeGetRequest(session, url, params)
	else:
        # print("LOGGING: makeGetRequest")
        # print("LOGGING: makeGetRequest: " + str(response.status_code))
		# logging.error('makeGetRequest:' + str(response.status_code))
		return None



def getUserInformation(session):
	url = 'https://api.spotify.com/v1/me'
	payload = makeGetRequest(session, url)

	if payload == None:
		return None

	return payload

"""
Gets the top tracks of a user for all three time intervals. Used to display the top
tracks on the TopTracks feature page.
Returns: A list of tracks IDs for each of the three time intervals
"""
def getAllTopTracks(session, limit=10):
    url = 'https://api.spotify.com/v1/me/top/tracks'
    track_ids = []
    time_range = ['short_term', 'medium_term', 'long_term']

    for time in time_range:
        track_range_ids = []

        params = {'limit': limit, 'time_range': time}
        payload = makeGetRequest(session, url, params)

        # print("------------------PAYLOAD---------------------")
        # print(payload)
        # print("------------------PAYLOAD  END-------------")

        if payload == None:
            return None

        for track in payload['items']:
            track_range_ids.append(track['id'])

        track_ids.append(track_range_ids)

    return track_ids

# TODO: situation where user has no tracks
def getAllTopArtists(session, limit=10):
    url = 'https://api.spotify.com/v1/me/top/artists'
    artist_names = []
    artist_ids = []
    time_range = ['short_term', 'medium_term', 'long_term']

    for time in time_range:
        track_range_ids = []

        params = {'limit': limit, 'time_range': time}
        payload = makeGetRequest(session, url, params)

        if payload == None:
            return None

        artist_range_names = []
        artist_range_ids = []

        for artist in payload['items']:
            artist_range_names.append(artist['name'])
            artist_range_ids.append(artist['id'])

        artist_names.append(artist_range_names)
        artist_ids.append(artist_range_ids)

    return artist_names, artist_ids

##############################
#       Yelp API Section     #
##############################
""" END POINTS """
# Business Search       URL -- 'https://api.yelp.com/v3/businesses/search'
# Phone Search          URL -- 'https://api.yelp.com/v3/businesses/search/phone'
# Transaction Search    URL -- 'https://api.yelp.com/v3/transactions/{transaction_type}/search'
# Business Details      URL -- 'https://api.yelp.com/v3/businesses/{id}'
# Business Match        URL -- 'https://api.yelp.com/v3/businesses/matches'
# Reviews               URL -- 'https://api.yelp.com/v3/businesses/{id}/reviews'
# Autocomplete          URL -- 'https://api.yelp.com/v3/autocomplete'

# Define my API key, Endpoint, and Header
API_KEY = 'nTM36O5k4QpcgkccZVAMhP8U4BxpO68EYzIA7KPXpRmnT31qUK49B7sfYQ2uA2_uzGRr94oA9aIxdD4PyIa0hyaXIccmnOGCVQ2tMJg4s3-a24CLE3syjaMHsqWRX3Yx'
ENDPOINT_PREFIX = 'https://api.yelp.com/v3/'
HEADERS = {'Authorization': 'bearer %s' % API_KEY}
EMPTY_RESPONSE = json.dumps('')

# render popular locations webpage / make yelp API calls with user input for 'term' key
@app.route("/popular_locations", methods=['GET'])
def popular_locations():
    # get user input from html form
    term = request.args.get('searchInput', None)

    # Check if user inputted a term
    if term == None:
        print("No term provided for business search, return nothing.")

    # Define Business Search paramters
    parameters = {
        'location': 'College Station, TX',
        'radius': 15000,
        'term': term,
        'sort_by': 'best_match',
        'limit': 50
    }

    # Make request to Yelp API
    url = ENDPOINT_PREFIX + 'businesses/search'
    response = requests.get(url, params = parameters, headers = HEADERS)

    # Check for good status code - if so, get JSON response and populate map
    if response.status_code == 200:
        print('Got 200 for business search')

        # Try/catch for invalid user input for 'term': key-value
        try:
            # Convert JSON string to dictionary
            businessSearchData = response.json()

            # Create dataframe from API response (businesses, list of dictionaries)
            dFrame = pd.DataFrame.from_dict(businessSearchData['businesses'])

            # YELP MAP - RESTAURANTS MARKED
            # Get latitude and longitude from Yelp API response
            cStatLat = 30.627977
            cStatLong = -96.334404

            # Generate base map of college station
            yelpMap = folium.Map(location = [cStatLat, cStatLong], zoom_start = 13)

            # Generate map of restaurants - Iterate through dataframe and add business markers
            for row in dFrame.index:
                latLong = dFrame['coordinates'][row]
                latitude = latLong['latitude']
                longitude = latLong['longitude']
                name = dFrame['name'][row]
                rating = dFrame['rating'][row]
                price = dFrame['price'][row]
                location = dFrame['location'][row]

                # Get address-1 from Location dictionary
                for loc in location.keys():
                    if loc == 'address1':
                        address = location[loc]

                # Create popup message for pin
                details = ('{}' + '<br><br>' + 'Address: {}' + '<br>' + 'Price: {}' + '<br>' + 'Rating: {}/5').format(name, address, price, rating)

                # Resize popup pin
                test = folium.Html(details, script = True)
                popup = folium.Popup(test, max_width = 300, min_width = 300)

                #  Create and business marker to map
                marker = folium.Marker(location = [latitude, longitude], popup = popup, icon = folium.Icon(color = "darkred"))
                marker.add_to(yelpMap)

            # Display map on webpage
            yelpMap.save('./templates/yelpMap.html')
        except KeyError:
            print('ERROR: User input provided an invalid key-value.')
            flash(f'There was an error with your input.', 'danger')
            return redirect(url_for('popular_locations'))
    else:
        print('Received non-200 response({}) for business search, returning empty response'.format(response.status_code))
        return EMPTY_RESPONSE
    return render_template('popularLocations.html', businessData = dFrame, isBusinessDataEmpty = dFrame.empty)

@app.route("/yelp_map")
def yelp_map():
    return render_template('yelpMap.html')

@app.route("/empty_yelp_map")
def empty_yelp_map():
    return render_template('./templates/blank_yelpMap.html')

if __name__ == '__main__':
    app.run(debug=True)
