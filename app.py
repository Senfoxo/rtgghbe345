import os
from flask import Flask, redirect, url_for, session, request, render_template, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import json
import requests
from datetime import datetime, timedelta
from models import db, User, Script, Follows
from config import Config
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

db.init_app(app)

csrf = CSRFProtect(app)
csrf.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

oauth = OAuth(app)
discord = oauth.register(
    name='discord',
    client_id=Config.DISCORD_CLIENT_ID,
    client_secret=Config.DISCORD_CLIENT_SECRET,
    authorize_url='https://discord.com/api/oauth2/authorize',
    authorize_params=None,
    access_token_url='https://discord.com/api/oauth2/token',
    access_token_params=None,
    refresh_token_url=None,
    client_kwargs={'scope': 'identify email guilds.join'},
)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.template_filter('get_time_ago')
def get_time_ago(time):
    now = datetime.utcnow()
    diff = now - time
    if diff < timedelta(minutes=1):
        return "just now"
    if diff < timedelta(hours=1):
        return f"{int(diff.total_seconds() // 60)} minutes ago"
    if diff < timedelta(days=1):
        return f"{int(diff.total_seconds() // 3600)} hours ago"
    return f"{int(diff.total_seconds() // 86400)} days ago"

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user is None:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

        if user.password_hash is None:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

        if check_password_hash(user.password_hash, password):
            login_user(user)
            user.last_seen = datetime.utcnow()
            db.session.commit()
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already taken!', 'danger')
            return redirect(url_for('register'))
        new_user = User(
            username=username,
            password_hash=generate_password_hash(password),
            avatar_url='assets/default_avatar.png',
            role='Member',
            role_color='#808080'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    return render_template('index.html', user=current_user)

@app.route('/scripts', methods=['GET', 'POST'])
@login_required
def scripts():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        content = request.form['content']

        new_script = Script(title=title, description=description, content=content, user_id=current_user.id)
        db.session.add(new_script)
        db.session.commit()

        return redirect(url_for('scripts'))
    
    all_scripts = Script.query.all()
    return render_template('scripts.html', user=current_user, scripts=all_scripts)

@app.route('/script/<int:script_id>')
@login_required
def script_detail(script_id):
    script = Script.query.get_or_404(script_id)
    return jsonify({
        'title': script.title,
        'description': script.description,
        'content': script.content,
        'username': script.user.username,
        'created_at': script.created_at.strftime('%Y-%m-%d %H:%M:%S')
    })

@app.route('/rawdata')
@login_required
def rawdata():
    profile_user = User.query.get(current_user.id)
    return render_template('rawdata.html', user=current_user, profile_user=profile_user)

@app.route('/create_rawdata')
@login_required
def create_rawdata():
    return render_template('create_rawdata.html', user=current_user)

@app.route('/profile')
@login_required
def profile():
    return redirect(url_for('view_profile', user_id=current_user.id))

@app.route('/profile/<int:user_id>')
@login_required
def view_profile(user_id):
    profile_user = User.query.get_or_404(user_id)
    posts = Script.query.filter_by(user_id=user_id).all()
    profile_user.last_seen = datetime.utcnow()
    db.session.commit()
    return render_template('view_profile.html', profile_user=profile_user, posts=posts, user=current_user)

@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    user = User.query.get_or_404(user_id)
    if user != current_user and user not in current_user.following:
        current_user.following.append(user)
        db.session.commit()
    return redirect(url_for('view_profile', user_id=user_id))

@app.route('/staff')
@login_required
def staff():
    staff_members = User.query.filter(User.role.in_(['Supporter(s)', 'Moderator(s)', 'Administrator(s)', 'Developer(s)'])).all()
    return render_template('staff.html', user=current_user, staff_members=staff_members)

@app.route('/tos')
@login_required
def tos():
    return render_template('tos.html', user=current_user)

@app.route('/changelogs')
@login_required
def changelogs():
    return render_template('changelogs.html', user=current_user)

@app.route('/get_scripts')
@login_required
def get_scripts():
    scripts = Script.query.all()
    return jsonify(scripts=[{
        'id': script.id,
        'title': script.title,
        'description': script.description,
        'content': script.content,
        'username': script.user.username,
        'user_avatar': script.user.avatar_url,
        'user_role': script.user.role,
        'role_color': script.user.role_color,
        'created_at': script.created_at.strftime('%Y-%m-%d %H:%M:%S'),
    } for script in scripts])

@app.route('/upload_script', methods=['POST'])
@login_required
def upload_script():
    data = request.get_json()
    if not data:
        return jsonify(success=False, error="No data provided"), 400

    title = data.get('title')
    description = data.get('description')
    script = data.get('script')

    if not title or not description or not script:
        return jsonify(success=False, error="All fields are required"), 400

    new_script = Script(
        title=title,
        description=description,
        content=script,
        user_id=current_user.id
    )
    db.session.add(new_script)
    db.session.commit()
    return jsonify(success=True)

@app.route('/vote_script/<int:script_id>', methods=['POST'])
@login_required
def vote_script(script_id):
    script = Script.query.get_or_404(script_id)
    data = request.json
    if data['vote_type'] == 'up':
        script.upvotes += 1
    elif data['vote_type'] == 'down':
        script.downvotes += 1
    db.session.commit()
    return jsonify(success=True, upvotes=script.upvotes, downvotes=script.downvotes)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
