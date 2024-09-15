from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, redirect, url_for, flash, session
from bcrypt import hashpw, gensalt, checkpw
from werkzeug.utils import secure_filename
import urllib.parse
import pymysql
import secrets
import random
import string
import smtplib
import time
import re
import os

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def send_email(subject, recipient, body):
    sender_email = "numbbvi@gmail.com"
    sender_password = "nqmhvhelsymlyanb"
    
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        return False

def db_connection():
    return pymysql.connect(
        host='numbbvi_db',
        user='numbbvi',
        password='N!u3661#',
        db='numbbvi',
        charset='utf8',
        cursorclass=pymysql.cursors.DictCursor
    )

def check_whitespace(string):
    return bool(re.search(r'\s', string))

def check_length(value, min_length, max_length):
    return len(value) >= min_length and len(value) <= max_length

def check_password(password):
    password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%~])[A-Za-z\d!@#$%&~]{10,}$"
    return re.match(password_regex, password)

def generate_email_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def get_profile_image():
    profile_images = ['chiikawa.jpg', 'hachiware.jpg', 'usagi.jpg']
    return random.choice(profile_images)

def utf_filename(filename):
    return urllib.parse.quote(filename)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_info(user_id):
    connection = db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM user WHERE user_id = %s", (user_id,))
            return cursor.fetchone()
    finally:
        connection.close()

@app.route('/', methods=['GET'])
def index():
    user = None
    if 'user_id' in session:
        user = get_user_info(session.get('user_id'))
    
    connection = db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM post ORDER BY post_time DESC")
            posts = cursor.fetchall()
    finally:
        connection.close()

    return render_template('index.html', user=user, posts=posts)

@app.route('/my_page', methods=['GET'])
def my_page():
    if 'user_id' not in session:
        flash('로그인 후 이용해주세요.', 'error')
        return redirect(url_for('login'))

    user = get_user_info(session.get('user_id'))
    return render_template('my_page.html', user=user)

@app.route('/check_pw', methods=['POST'])
def check_pw():
    if 'user_id' not in session:
        flash('로그인 후 이용해주세요.', 'error')
        return redirect(url_for('login'))
    
    user_pw = request.form.get('pw', '').strip()
    user_id = session.get('user_id')
    
    connection = db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT user_pw FROM user WHERE user_id = %s", (user_id,))
            user = cursor.fetchone()
            
            if not user or not checkpw(user_pw.encode('utf-8'), user['user_pw'].encode('utf-8')):
                flash("비밀번호가 일치하지 않습니다.", 'error')
                return redirect(url_for('my_page'))
            else:
                session['check_pw'] = True
                return redirect(url_for('my_page'))

    except Exception as e:
        flash('오류가 발생했습니다. 다시 접속해주세요.', 'error')
        return redirect(url_for('my_page'))
    finally:
        connection.close()
            
@app.route('/user_modify', methods=['POST'])
def user_modify():
    if 'check_pw' not in session:
        flash('비밀번호를 확인해주세요.', 'error')
        return redirect(url_for('my_page'))

    user_name = request.form.get('name', '').strip()
    school = request.form.get('school', '').strip()
    email = request.form.get('email', '').strip()
    new_pw = request.form.get('new_pw', '').strip()
    check_new_pw = request.form.get('check_new_pw', '').strip()
    user_id = session.get('user_id')
    file = request.files.get('file')

    if not user_name or not school or not email:
        flash("빈칸 없이 작성해주세요.", 'error')
        return redirect(url_for('my_page'))

    if not check_length(user_name, 3, 10):
        flash("이름은 3~10글자로 입력해주세요.", 'error')
        return redirect(url_for('my_page'))

    if new_pw:
        if not check_password(new_pw):
            flash("비밀번호는 영어 대소문자, 숫자, 특수문자(!@#$%&~)를 포함하여 최소 10글자 이상이어야 합니다.", 'error')
            return redirect(url_for('my_page'))
        
    if new_pw != check_new_pw:
        flash("새 비밀번호가 일치하지 않습니다.", 'error')
        return redirect(url_for('my_page'))

    profile_image_filename = None
    if file and file.filename != '':
        if not allowed_file(file.filename):
            flash('허용되지 않은 파일 형식입니다. png, jpg, jpeg, gif 파일만 업로드 가능합니다.', 'error')
            return redirect(url_for('my_page'))

        filename = utf_filename(file.filename)
        timestamp = str(int(time.time()))
        unique_filename = f"{timestamp}_{filename}"
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
        profile_image_filename = unique_filename

    connection = db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT email FROM user WHERE user_id = %s", (user_id,))
            current_user = cursor.fetchone()

            if current_user['email'] != email:
                session['new_user_info'] = {
                    'name': user_name,
                    'school': school,
                    'email': email,
                    'new_pw': new_pw,
                    'profile_image_filename': profile_image_filename
                }
                session['email_code'] = generate_email_code()
                session['user_modify'] = True

                subject = '회원정보 수정 인증 코드'
                body = f'{user_name}님, 다음 인증 코드를 입력해 주세요: {session["email_code"]}'
                if send_email(subject, email, body):
                    flash('인증 코드가 이메일로 전송되었습니다.', 'success')
                    return redirect(url_for('check_email'))
                else:
                    flash('이메일 전송에 실패했습니다.', 'error')
                    return redirect(url_for('my_page'))

            if new_pw:
                hashed_pw = hashpw(new_pw.encode('utf-8'), gensalt())
                cursor.execute("UPDATE user SET user_pw=%s WHERE user_id=%s", (hashed_pw, user_id))

            if profile_image_filename:
                cursor.execute(
                    "UPDATE user SET name=%s, school=%s, profile_image=%s WHERE user_id=%s",
                    (user_name, school, profile_image_filename, user_id)
                )
                session['profile_image'] = profile_image_filename
            else:
                cursor.execute(
                    "UPDATE user SET name=%s, school=%s WHERE user_id=%s",
                    (user_name, school, user_id)
                )
            connection.commit()

            flash('회원정보가 수정되었습니다.', 'success')
            return redirect(url_for('my_page'))

    except Exception as e:
        flash('오류가 발생했습니다. 다시 시도해주세요.', 'error')
        return redirect(url_for('my_page'))
    finally:
        connection.close()
        
@app.route('/user_list', methods=['GET'])
def user_list():
    user = None
    if 'user_id' in session:
        user = get_user_info(session.get('user_id'))
        
    connection = db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id, name, user_id, school, email, profile_image FROM user")
            users = cursor.fetchall()
    finally:
        connection.close()

    return render_template('user_list.html', user=user, users=users)

@app.route('/user_show', methods=['GET'])
def user_show():
    user = None
    if 'user_id' in session:
        user = get_user_info(session.get('user_id'))
    
    user_id = request.args.get('user_id', '')
    connection = db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT name, user_id, school, email, profile_image FROM user WHERE id=%s", (user_id, ))
            users = cursor.fetchone()
    finally:
        connection.close()
        
    return render_template('user_show.html', user=user, users=users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        session.clear()
        flash('로그아웃 되었습니다.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        user_name = request.form.get('name', '')
        user_id = request.form.get('id', '').strip()
        user_pw = request.form.get('pw', '').strip()
        school = request.form.get('school', '').strip()
        email = request.form.get('email', '').strip()

        profile_image = get_profile_image()
        
        if not user_name or not user_id or not user_pw or not school or not email:
            flash("빈칸없이 작성해주세요.", "error")
            return redirect(url_for('register'))

        if check_whitespace(user_id) or check_whitespace(user_pw):
            flash("아이디나 비밀번호에 공백을 포함할 수 없습니다.", 'error')
            return redirect(url_for('register'))

        if not check_length(user_name, 3, 10):
            flash("이름은 3~10글자로 입력해주세요.", 'error')
            return redirect(url_for('register'))

        if not check_length(user_id, 3, 10):
            flash("아이디는 3~10글자로 입력해주세요.", 'error')
            return redirect(url_for('register'))

        if not check_password(user_pw):
            flash("비밀번호는 영어 대소문자, 숫자, 특수문자(!@#$%&~)를 포함하여 최소 10글자 이상이어야 합니다.", 'error')
            return redirect(url_for('register'))
        
        connection = db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM user WHERE user_id = %s", (user_id,))
                existing_user_id = cursor.fetchone()
                
                if existing_user_id:
                    flash("이미 등록된 아이디입니다.", 'error')
                    return redirect(url_for('register'))

                cursor.execute("SELECT * FROM user WHERE email = %s", (email,))
                existing_email = cursor.fetchone()

                if existing_email:
                    flash("이미 등록된 이메일입니다.", 'error')
                    return redirect(url_for('register'))
        except Exception as e:
            flash('오류가 발생했습니다. 다시 접속해주세요.', 'error')
            return redirect(url_for('register'))
        finally:
            connection.close()
        
        email_code = generate_email_code()

        session['name'] = user_name
        session['id'] = user_id
        session['pw'] = hashpw(user_pw.encode('utf-8'), gensalt())
        session['school'] = school
        session['email'] = email
        session['profile_image'] = profile_image
        session['email_code'] = email_code

        subject = '회원가입 인증 코드'
        body = f'{user_name}님, 안녕하세요.\n\nnumbbvi\'s blog의 회원가입을 완료하려면 다음 인증 코드를 입력해 주세요: {email_code}'
        if send_email(subject, email, body):
            flash('인증 코드가 이메일로 전송되었습니다. 이메일을 확인해주세요.', 'success')
            return redirect(url_for('check_email'))
        else:
            flash('이메일 전송에 실패했습니다.', 'error')
            return redirect(url_for('register'))

@app.route('/check_email', methods=['GET', 'POST'])
def check_email():
    if not (session.get('name') and session.get('id') and session.get('pw')
        and session.get('school') and session.get('email') and session.get('profile_image')):
        return render_template('register.html')

    if request.method == 'POST':
        user_code = request.form.get('email_code', '').strip()

        if user_code == session.get('email_code'):
            connection = db_connection()
            try:
                with connection.cursor() as cursor:
                    sql = """
                    INSERT INTO user (name, user_id, user_pw, school, email, profile_image)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """
                    cursor.execute(sql, (session['name'], session['id'], session['pw'], session['school'], session['email'], session['profile_image']))
                    connection.commit()
            except Exception as e:
                flash('회원가입 중 오류가 발생했습니다.', 'error')
                return redirect(url_for('register'))
            finally:
                connection.close()

            session.pop('name', None)
            session.pop('id', None)
            session.pop('pw', None)
            session.pop('school', None)
            session.pop('email', None)
            session.pop('email_code', None)

            flash('회원가입이 완료되었습니다.', 'success')
            return redirect(url_for('login'))

        else:
            flash('인증 코드가 잘못되었습니다. 다시 시도해주세요.', 'error')
            return redirect(url_for('check_email'))

    return render_template('check_email.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        session.clear()
        flash('로그아웃 되었습니다.', 'success')
        return redirect(url_for('login'))
    
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        user_id = request.form.get('id', '').strip()
        user_pw = request.form.get('pw', '').strip()

        connection = db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM user WHERE user_id = %s", (user_id,))
                user = cursor.fetchone()
        finally:
            connection.close()

        if user and checkpw(user_pw.encode('utf-8'), user['user_pw'].encode('utf-8')):
            session['user_id'] = user_id
            session['user_name'] = user['name']
            session['profile_image'] = user['profile_image']
            return redirect(url_for('index'))
        else:
            flash('로그인에 실패하였습니다.', 'error')
            return render_template('login.html')

@app.route('/logout', methods=['GET'])
def logout():
    if 'user_id' in session:
        session.clear()
        flash('로그아웃 되었습니다.', 'success')
        return redirect(url_for('login'))
    else:
        return redirect(url_for('login'))

@app.route('/find_id', methods=['GET', 'POST'])
def find_id():
    if 'user_id' in session:
        session.clear()
        flash('로그아웃 되었습니다.', 'success')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('find_id.html')
    elif request.method == 'POST':
        user_name = request.form.get('name', '').strip()
        school = request.form.get('school', '').strip()
        email = request.form.get('email', '').strip()

        connection = db_connection()
        try:
            with connection.cursor() as cursor:
                sql = """
                SELECT user_id FROM user
                WHERE name=%s AND school=%s AND email=%s
                """
                cursor.execute(sql, (user_name, school, email))
                user = cursor.fetchone()
        finally:
            connection.close()

        if user:
            subject = '아이디 찾기 결과'
            body = f'{user_name}님, 요청하신 아이디는 {user["user_id"]} 입니다.'
            if send_email(subject, email, body):
                flash('아이디가 이메일로 전송되었습니다.', 'success')
                return redirect(url_for('login'))
            else:
                flash('이메일 전송에 실패했습니다.', 'error')
                return redirect(url_for('find_id'))
        else:
            flash('입력하신 정보와 일치하는 아이디가 없습니다.', 'error')
            return redirect(url_for('find_id'))

@app.route('/find_pw', methods=['GET', 'POST'])
def find_pw():
    if 'user_id' in session:
        session.clear()
        flash('로그아웃 되었습니다.', 'success')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('find_pw.html')
    elif request.method == 'POST':
        user_name = request.form.get('name', '').strip()
        user_id = request.form.get('id', '').strip()
        school = request.form.get('school', '').strip()
        email = request.form.get('email', '').strip()

        connection = db_connection()
        try:
            with connection.cursor() as cursor:
                sql = """
                SELECT * FROM user
                WHERE name=%s AND user_id=%s AND school=%s AND email=%s
                """
                cursor.execute(sql, (user_name, user_id, school, email))
                user = cursor.fetchone()

            if user:
                temp_password = ''.join(random.choices(string.ascii_letters + string.digits, k=15))
                hashed_temp_password = hashpw(temp_password.encode('utf-8'), gensalt())

                with connection.cursor() as cursor:
                    sql = "UPDATE user SET user_pw = %s WHERE user_id = %s"
                    cursor.execute(sql, (hashed_temp_password, user_id))
                    connection.commit()

                subject = '비밀번호 찾기'
                body = f'{user_name}님, 임시 비밀번호는 {temp_password} 입니다. 로그인 후 비밀번호를 변경해주세요.'
                if send_email(subject, email, body):
                    flash('임시 비밀번호가 이메일로 전송되었습니다.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('이메일 전송에 실패했습니다.', 'error')
                    return redirect(url_for('find_pw'))
            else:
                flash('입력하신 정보와 일치하는 계정이 없습니다.', 'error')
                return redirect(url_for('find_pw'))
        finally:
            connection.close()

@app.route('/post_create', methods=['GET', 'POST'])
def post_create():
    user = None
    if 'user_id' in session:
        user = get_user_info(session.get('user_id'))
    else:
        flash('로그인 후 이용해주세요.', 'error')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('post_create.html', user=user)
    
    elif request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        is_secret = request.form.get('is_secret') == 'on'
        secret_pw = request.form.get('secret_pw').strip()
        file = request.files.get('file')

        if not title or not content:
            flash('제목과 내용을 모두 입력해주세요.', 'error')
            return redirect(url_for('post_create'))

        if is_secret and not secret_pw:
            flash('비밀글의 비밀번호를 입력해주세요.', 'error')
            return redirect(url_for('post_create'))
        elif not is_secret and secret_pw:
            flash('비밀글 설정을 정확히 해주세요.', 'error')
            return redirect(url_for('post_create'))

        unique_filename = None
        if file and file.filename != '':
            if not allowed_file(file.filename):
                flash('허용되지 않은 파일 형식입니다.', 'error')
                return redirect(url_for('post_create'))
            
            filename = secure_filename(file.filename)
            timestamp = str(int(time.time()))
            unique_filename = f"{timestamp}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))

        if is_secret:
            secret_pw = hashpw(secret_pw.encode('utf-8'), gensalt()).decode('utf-8')

        connection = db_connection()
        try:
            with connection.cursor() as cursor:
                sql = """
                INSERT INTO post (title, content, file_name, is_secret, secret_pw, user_id)
                VALUES (%s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (title, content, unique_filename, is_secret, secret_pw, session.get('user_id')))
                connection.commit()
        except Exception as e:
            flash('오류가 발생했습니다. 다시 시도해주세요.', 'error')
            return redirect(url_for('post_create'))
        finally:
            connection.close()

        flash('게시글이 성공적으로 작성되었습니다.', 'success')
        return redirect(url_for('index'))
    
@app.route('/secret_pw', methods=['GET', 'POST'])
def secret_pw():
    user = None
    if 'user_id' in session:
        user = get_user_info(session.get('user_id'))

    post_id = request.args.get('post_id', '').strip()

    connection = db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM post WHERE id = %s", (post_id,))
            post = cursor.fetchone()
    finally:
        connection.close()

    if request.method == 'GET':
        return render_template('secret_pw.html', user=user, post=post)
    
    elif request.method == 'POST':
        secret_pw = request.form.get('secret_pw', '').strip()

        if post and checkpw(secret_pw.encode('utf-8'), post['secret_pw'].encode('utf-8')):
            session[f'secret_{post_id}'] = True
            return redirect(url_for('post_show', user=user, post_id=post_id))
        else:
            flash('비밀번호가 일치하지 않습니다.', 'error')
            return redirect(url_for('secret_pw', user=user, post_id=post_id))
    
@app.route('/post_show', methods=['GET'])
def post_show():
    user = None
    if 'user_id' in session:
        user = get_user_info(session.get('user_id'))
        
    post_id = request.args.get('post_id', '').strip()
    
    connection = db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM post WHERE id = %s", (post_id,))
            post = cursor.fetchone()
    finally:
        connection.close()
        
    if post and post['is_secret'] and not session.get(f'secret_{post_id}'):
        return redirect(url_for('secret_pw', post_id=post_id))

    if post and post.get('file_name'):
        post['original_filename'] = post['file_name'].split('_', 1)[1]

    if post:
        return render_template('post_show.html', user=user, post=post)
    else:
        flash('해당 게시글을 찾을 수 없습니다.', 'error')
        return redirect(url_for('index'))

@app.route('/post_modify', methods=['GET', 'POST'])
def post_modify():
    if 'user_id' not in session:
        flash('로그인 후 이용해주세요.', 'error')
        return redirect(url_for('login'))

    if request.method == 'GET':
        user = get_user_info(session.get('user_id'))
        post_id = request.args.get('post_id', '').strip()
        
        connection = db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM post WHERE id=%s", (post_id,))
                post = cursor.fetchone()
                if post and post['file_name']:
                    post['original_filename'] = post['file_name'].split('_', 1)[1]
        finally:
            connection.close()

        if not post:
            flash('게시글을 찾을 수 없습니다.', 'error')
            return redirect(url_for('index'))

        if session.get('user_id') != post['user_id']:
            flash('게시글을 수정할 권한이 없습니다.', 'error')
            return redirect(url_for('index'))

        return render_template('post_modify.html', user=user, post=post)

    elif request.method == 'POST':
        post_id = request.form.get('post_id', '').strip()
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        file = request.files.get('file')

        connection = db_connection()
        try:
            with connection.cursor() as cursor:
                unique_filename = None
                if file and file.filename != '':
                    if not allowed_file(file.filename):
                        flash('허용되지 않은 파일 형식입니다. png, jpg, jpeg, gif 파일만 업로드 가능합니다.', 'error')
                        return redirect(url_for('post_modify', post_id=post_id))
                    
                    filename = secure_filename(file.filename)
                    timestamp = str(int(time.time()))
                    unique_filename = f"{timestamp}_{filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))

                    sql = "UPDATE post SET title=%s, content=%s, file_name=%s WHERE id=%s"
                    cursor.execute(sql, (title, content, unique_filename, post_id))
                else:
                    sql = "UPDATE post SET title=%s, content=%s WHERE id=%s"
                    cursor.execute(sql, (title, content, post_id))

                connection.commit()
                flash('게시글이 성공적으로 수정되었습니다.', 'success')
        finally:
            connection.close()

        return redirect(url_for('post_show', post_id=post_id))

@app.route('/post_delete', methods=['GET'])
def post_delete():
    user = None
    if 'user_id' in session:
        user = get_user_info(session.get('user_id'))
    else:
        flash('로그인 후 이용해주세요.', 'error')
        return redirect(url_for('login'))

    post_id = request.args.get('post_id', '').strip()

    connection = db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM post WHERE id=%s", (post_id,))
            post = cursor.fetchone()
    finally:
        connection.close()

    if not post:
        flash('게시글을 찾을 수 없습니다.', 'error')
        return redirect(url_for('index'))

    if session.get('user_id') != post['user_id']:
        flash('게시글을 삭제할 권한이 없습니다.', 'error')
        return redirect(url_for('index'))

    if post['file_name']:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], post['file_name'])
        if os.path.exists(file_path):
            os.remove(file_path)

    connection = db_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute("DELETE FROM post WHERE id=%s", (post_id,))
            connection.commit()
    finally:
        connection.close()

    flash('게시글이 성공적으로 삭제되었습니다.', 'success')
    return redirect(url_for('index'))

@app.route('/search', methods=['GET', 'POST'])
def search():
    search_category = request.args.get('search_category', '')
    query = request.args.get('search', '').strip()
    
    user = None
    if 'user_id' in session:
        user = get_user_info(session.get('user_id'))

    if search_category and query:
        connection = db_connection()
        try:
            with connection.cursor() as cursor:
                if search_category == 'title':
                    sql = "SELECT * FROM post WHERE title LIKE %s"
                    cursor.execute(sql, ("%" + query + "%",))
                elif search_category == 'content':
                    sql = "SELECT * FROM post WHERE content LIKE %s"
                    cursor.execute(sql, ("%" + query + "%",))
                elif search_category == 'all':
                    sql = "SELECT * FROM post WHERE title LIKE %s OR content LIKE %s"
                    cursor.execute(sql, ("%" + query + "%", "%" + query + "%"))
                results = cursor.fetchall()
        finally:
            connection.close()

        return render_template('search.html', results=results, query=query, search_category=search_category, user=user)
    else:
        return render_template('search.html', results=[], query=query, search_category=search_category, user=user)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)