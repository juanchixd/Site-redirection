import os
import requests
import csv
from flask import Flask, render_template, redirect, abort, request, flash, url_for
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def get_id(self):
        return "1"

@login_manager.user_loader
def load_user(user_id):
    return User()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = bcrypt.generate_password_hash(os.environ.get('PASSWORD')).decode('utf-8')
        if username == os.environ.get('USER') and bcrypt.check_password_hash(hashed_password, password):
            user = User()
            login_user(user)
            return redirect('/')
        else:
            flash('Usuario o contraseña incorrectos.', 'error')
    return render_template('login.html', now=datetime.now())

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/')
@login_required
def index():
    try:
        sheet_url = os.environ.get("GOOGLE_SHEET_URL")
        try:
            response = requests.get(sheet_url)
            response.raise_for_status()
            data = response.text
        except requests.exceptions.RequestException as e:
            abort(500)
        redirections = []
        reader = csv.reader(data.splitlines())
        next(reader)
        for row in reader:
            source_path, target_url = row[0], row[1]
            if not target_url.startswith('http'):
                target_url = 'http://' + target_url
            redirections.append({'source_path': source_path, 'target_url': target_url})

        return render_template('index.html', redirections=redirections)
    except Exception as e:
        abort(500, f'Error al cargar los datos desde el Google Sheet: {e}')

@app.errorhandler(401)
def unauthorized(error):
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)