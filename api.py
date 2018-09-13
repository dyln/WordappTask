from flask import Flask, request, jsonify, make_response, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import os
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from functools import wraps
import urllib2
import json

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'mobile_blog.db')
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'posts.db')
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'comments.db')
## facebook app id = 1862171063899187
## facebook secret = b9d0553846e525d053aeb4e30ab3db26
## FACEBOOK ACCESS TOKEN = EAAadonzGVDMBAKlrGxQPoig9mzkkyByZBHt3NxbDcyRqoNBZCRk8UgVImGQ7HfWJO0cuKZCLFtt0tgZC8z9di5QDpDF8wbiYZAYi6FytZByKlMnXnGj9nUzOu0yZCwSwxtVt6Wm1eZBXMiEenll7usu62G3EVZAGxYxgm0HuZBgnZB9qEDFcAraoIIomjIZApRcG2srUlxSiowBTGtixncJULmzR

fb_access_token = "EAAadonzGVDMBAKlrGxQPoig9mzkkyByZBHt3NxbDcyRqoNBZCRk8UgVImGQ7HfWJO0cuKZCLFtt0tgZC8z9di5QDpDF8wbiYZAYi6FytZByKlMnXnGj9nUzOu0yZCwSwxtVt6Wm1eZBXMiEenll7usu62G3EVZAGxYxgm0HuZBgnZB9qEDFcAraoIIomjIZApRcG2srUlxSiowBTGtixncJULmzR"
fb_url = "https://graph.facebook.com/v3.1/me?fields=id%2Cname%2Cabout%2Cemail&access_token="

facebook_blueprint = make_facebook_blueprint(client_id='1862171063899187', client_secret='b9d0553846e525d053aeb4e30ab3db26')
app.register_blueprint(facebook_blueprint, url_prefix='/facebook_login')
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    password = db.Column(db.String(50))
    email = db.Column(db.String(25))
    admin = db.Column(db.Boolean)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(280))
    user_id = db.Column(db.Integer)
    file_path = db.Column(db.String(100))
    draft = db.Column(db.Boolean)
    publish = db.Column(db.Boolean)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer)
    text = db.Column(db.String(280))
    user_id = db.Column(db.Integer)
    visible = db.Column(db.Boolean)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(50))
    complete = db.Column(db.Boolean)
    user_id = db.Column(db.Integer)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

#bura gidicek
#facebook id gelcek o idden usera bakcak
#appten facebook id(12 hane), id'i al graph api kullanarak bak kimmis, varsa gir yoksa kayit ol ?

#USE THIS
#curl -i -X GET \
 # "https://graph.facebook.com/v3.1/me?fields=id%2Cname%2Cabout%2Cemail&access_token=EAAadonzGVDMBAK3JXox2caX8XZCFJCIkF8bI3HpVriQibBmfP6hLGdm6rILXitdSwxKYvMFzMb9cPAb0M1zITTGcm7f17V97IKRCzDKApTI5UJCQrqWUvCIHpCjnNI0teATTxBlYtTcY2BmOJ3fCZCEN8DDSGwMvkuGU2sxsvWm5Kylrjve9a0is0YrCb0jWAeoAjfdY5ZAkmVuUMbdtmb4NBNW2cYEzmjt4xgr2VdxZBOz7fVS0"
@app.route('/facebook')
def facebook_login():
    if not facebook.authorized:
        return redirect(url_for('facebook.login'))
    account_info= facebook.get('public_profile.json')

    if account_info.ok:
        account_info_json=account_info.json()
        return '<h1> Your Facebook name is @{}</h1>'.format(account_info_json['name'])
    
    return '<h1>Request failed!</h1>'
 
 #####   

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):#current_user):

    if not current_user.admin:
       return jsonify({'message' : 'Cannot perform that function!'})
    
    users = User.query.all()
    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['name'] = user.name
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    
    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})
    
    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['name'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):#current_user):
    data = request.get_json() #BURAYA FACEBOOK SIGN UP GELCEK SANIRIM

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, admin = False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New User created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})
    
    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()    
    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization
    
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})
    
    user = User.query.filter_by(name=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/signup', methods=['POST'])
def signup():
    auth = request.authorization

    if 'x-access-token' in request.headers:
        return jsonify({'message' : 'Already signed in.'})
    
    data = request.get_json() 
    
    if "@" not in data['email']:
        return jsonify({'message' : 'Please enter a valid e-mail adress.'})

    user = User.query.filter_by(email=data['email']).first()
    #print (user)
    
    #print (user.email)
    if user:
        return jsonify({'message' : 'E-mail is already in use.'})
    
    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password,email=data['email'], admin = False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New User created! You can now login.'})

@app.route('/signup/facebook', methods=['POST'])
def fbsignup():
    data_raw = urllib2.urlopen(fb_url+fb_access_token)
    data = json.load(data_raw)

    hashed_password = generate_password_hash(data['email'], method='sha256') ## !!!!

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password,email=data['email'], admin = False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New User created! You can now login.'})


if __name__ == '__main__':
    app.run(debug=True)

