from flask import abort, Flask, render_template, send_from_directory, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, UserForm, EmailForm, NewPassForm, LoginForm, CommentForm, MessageForm, \
    MetersForm
from flask_gravatar import Gravatar
from bleach import clean
from functools import wraps
import smtplib
from my_conf_google import EMAIL, SMTP_HOST
from email.message import Message
import os
import re
import jwt

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['CKEDITOR_LANGUAGE'] = 'ru'
ckeditor = CKEditor(app)
Bootstrap(app)


# Year for all templates
@app.context_processor
def inject_year():
    return {'year': datetime.now().year}


# CONNECT TO DB
db_url = os.environ.get("DATABASE_URL")
if db_url:
    db_url = db_url.replace("://", "ql://", 1)
else:
    db_url = "sqlite:///blog.db"
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Connect to LoginManager
login_manager = LoginManager()
login_manager.init_app(app)

# Gravatar
gravatar = Gravatar(app,
                    size=80,
                    rating='g',
                    default='identicon',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# CONFIGURE TABLES
class AbsTable:
    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class User(UserMixin, db.Model, AbsTable):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    level = db.Column(db.Integer, nullable=False)
    apartment = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    email_check = db.Column(db.BOOLEAN)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    date = db.Column(db.String(25), nullable=False)
    posts = relationship('BlogPost', cascade="all, delete", back_populates='author')
    comments = relationship('Comment', cascade="all, delete", back_populates='c_author')
    sent_notif = relationship('Notification', foreign_keys='Notification.author_id', cascade='all, delete',
                              back_populates='n_author')
    received_notif = relationship('Notification', foreign_keys='Notification.recipient_id', cascade='all, delete',
                                  back_populates='recipient')


class BlogPost(db.Model, AbsTable):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship('User', back_populates='posts')
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(100), nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(25), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    post_comments = relationship('Comment', cascade="all, delete", back_populates='post')


class Comment(db.Model, AbsTable):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(25), nullable=False)
    text = db.Column(db.Text, nullable=False)
    c_author = relationship('User', back_populates='comments')
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post = relationship('BlogPost', back_populates='post_comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


class Notification(db.Model, AbsTable):
    __tablename__ = 'notifications'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(25), nullable=False)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    n_author = relationship('User', foreign_keys=[author_id], back_populates='sent_notif')
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    recipient = relationship('User', foreign_keys=[recipient_id], back_populates='received_notif')


# db.create_all()

# Strip invalid/dangerous tags/attributes
def clean_html(content):
    allowed_tags = ['a', 'abbr', 'acronym', 'address', 'b', 'br', 'dl', 'dt',
                    'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img',
                    'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike', 'strong',
                    'span', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
                    'thead', 'tr', 'tt', 'u', 'ul', 'iframe']
    allowed_attrs = {'a': ['href', 'target', 'title'], 'img': ['src', 'alt'],
                     'iframe': ['src', 'title', 'frameborder', 'allow', 'allowfullscreen']}
    cleaned = clean(content, tags=allowed_tags, attributes=allowed_attrs, strip=True)
    return cleaned


# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Current datetime
def date_time():
    return (datetime.now() + timedelta(hours=3)).isoformat(' ', 'seconds')


def format_phone(phone):
    phone = re.sub('\D', '', phone)
    if len(phone) == 10:
        return f'+7{phone}'
    if len(phone) == 11:
        return f'+7{phone[1:]}'
    return phone


# Protect routes
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.level == 5:
            return f(*args, **kwargs)
        return abort(403)

    return decorated_function


def moderator(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.level > 3:
            return f(*args, **kwargs)
        return abort(403)

    return decorated_function


def news_writer(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.level > 2:
            return f(*args, **kwargs)
        return abort(403)

    return decorated_function


def send_email(to, subj, html_content):
    msg = Message()
    msg['Subject'] = subj
    msg['From'] = EMAIL
    msg['To'] = to
    msg['content-type'] = 'text/html'
    msg.set_payload(html_content, charset='utf-8')
    with smtplib.SMTP(SMTP_HOST, port=587) as conn:
        conn.starttls()
        conn.login(user=EMAIL, password=os.environ.get('PASS'))
        conn.send_message(msg)


# ROUTES
@app.route('/')
# def get_all_posts():
#     posts = BlogPost.query.order_by(BlogPost.id).all()
#     return render_template("index.html", all_posts=posts)
def hello():
    return redirect("https://nov2.ru/", code=302)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).first():
            flash("Этот email уже зарегистрирован")
            return redirect(url_for('login', email=email))
        user_hash = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16)
        new_user = User(name=form.name.data,
                        lastname=form.lastname.data,
                        apartment=form.apartment.data,
                        phone=format_phone(form.phone.data),
                        level=1,
                        email=email,
                        email_check=False,
                        password=user_hash,
                        date=date_time())
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        flash('Подтвердите EMAIL, чтобы активировать аккаунт.')
        return redirect(url_for('check_email'))
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    email = request.args.get('email')
    if email:
        form.email.data = email
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            flash('Этот email не зарегистрирован.', 'error')
            return redirect(url_for('login'))
        if not check_password_hash(user.password, form.password.data):
            flash('Пароль неверный', 'error')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Войдите или зарегистрируйтесь чтобы комментировать')
            return redirect(url_for('login'))
        if not current_user.email_check:
            flash('Подтвердите EMAIL чтобы комментировать.')
            return redirect(url_for('personal'))
        if current_user.level < 2:
            flash('Вы не можете комментировать.')
            return redirect(url_for('contact'))
        text = clean_html(form.text.data)
        if current_user.level < 4:
            text = text.replace('iframe', '')
        new_comment = Comment(text=text,
                              date=date_time(),
                              c_author=current_user,
                              post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=requested_post.id))
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=['GET', 'POST'])
def contact():
    form = MessageForm()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('Войдите или зарегистрируйтесь для отправки сообщений.')
            return redirect(url_for('login'))
        content = f"<p><b>Имя: {current_user.name} {current_user.lastname}</b></p>" \
                  f"<p><b>Email: {current_user.email}</b></p>" \
                  f"<p><b>Телефон: {current_user.phone}</b></p><p>" \
                  f"<p><b>Зарегистрирован: {current_user.date}</b></p>" \
                  f"<b>Квартира: {current_user.apartment}</b></p>" \
                  f"<p><b>Уровень доступа: {current_user.level}</b></p>" \
                  f"{clean_html(form.text.data).replace('iframe', '')}"
        send_email('9084073@mail.ru', 'Сообщение с сайта Новосмоленская 2', content)
        send_email('mishau7@gmail.com', 'Сообщение с сайта Новосмоленская 2', content)
        send_email('ns2noreply@gmail.com', 'Сообщение с сайта Новосмоленская 2', content)
        flash('Ваше сообщение отправлено успешно.')
        return redirect(url_for('contact'))
    return render_template("contact.html", form=form)


@app.route("/new-post", methods=['GET', 'POST'])
@news_writer
def add_new_post():
    form = CreatePostForm(
        img_url='https://upload.wikimedia.org/wikipedia/commons/thumb/5/56/'
                'Новосмоленские_башни.jpg/1280px-Новосмоленские_башни.jpg')
    if form.validate_on_submit():
        new_post = BlogPost(title=form.title.data,
                            subtitle=form.subtitle.data,
                            body=clean_html(form.body.data),
                            img_url=form.img_url.data,
                            author=current_user,
                            date=date_time())
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@news_writer
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    if current_user.id != post.author_id and current_user.level < 4:
        return redirect(url_for("show_post", post_id=post.id))
    edit_form = CreatePostForm(title=post.title,
                               subtitle=post.subtitle,
                               img_url=post.img_url,
                               body=post.body)
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = clean_html(edit_form.body.data)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@news_writer
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    if current_user.id == post_to_delete.author_id or current_user.level > 3:
        db.session.delete(post_to_delete)
        db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete/post/<int:post_id>/comment/<int:comment_id>")
def delete_comment(post_id, comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    if current_user.id == comment_to_delete.author_id or current_user.level > 3:
        db.session.delete(comment_to_delete)
        db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))


@app.route("/personal/<int:n_id>")
def delete_notif(n_id):
    notif_to_delete = Notification.query.get(n_id)
    if current_user.level >= notif_to_delete.n_author.level or current_user.id == notif_to_delete.recipient_id:
        db.session.delete(notif_to_delete)
        db.session.commit()
    if request.args.get('admin'):
        return redirect(url_for('edit_user', user_id=request.args.get('user_id')))
    return redirect(url_for('personal'))


@app.route("/personal", methods=['GET', 'POST'])
def personal():
    if current_user.is_authenticated:
        form = MetersForm()
        if form.validate_on_submit():
            subj = f'Показания квартиры {current_user.apartment} с сайта Новосмоленская 2'
            content = f"<p><b>Имя: {current_user.name} {current_user.lastname}</b></p>" \
                      f"<p><b>Email: {current_user.email}</b></p>" \
                      f"<p><b>Email проверен: {current_user.email_check}</b></p>" \
                      f"<p><b>Телефон: {current_user.phone}</b></p>" \
                      f"<p><b>Зарегистрирован: {current_user.date}</b></p>" \
                      f"<p><b>Квартира: {current_user.apartment}</b></p>" \
                      f"<p><b>Холодная вода: {form.cold_water.data}</b></p>" \
                      f"<p><b>Горячая вода: {form.hot_water.data}</b></p>" \
                      f"<p><b>Дата: {date_time()}</b></p>"
            send_email('ns2buh@mail.ru', subj, content)
            flash("Показания переданы успешно.", "info")
            return redirect(url_for('personal'))
        return render_template('personal.html', form=form)
    return redirect(url_for('get_all_posts'))


@app.route("/personal/email")
def check_email():
    code = jwt.encode({'email': current_user.email}, app.config.get('SECRET_KEY'), algorithm='HS256')
    content = f"<p><b>Для подтверждения перейдите по ссылке:</b></p>" \
              f"<a target='_blank' href='{url_for('verify_email', code=code, _external=True)}'>ПОДТВЕРДИТЬ</a>"
    send_email(current_user.email, "Подтверждение email для сайта Новосмоленская 2", content)
    flash('Ссылка для подтверждения отправлена на ваш EMAIL.')
    return redirect(url_for('personal'))


@app.route("/personal/email/<code>")
def verify_email(code):
    data = jwt.decode(code, app.config.get('SECRET_KEY'), algorithms=['HS256'])
    email = data["email"]
    if current_user.email == email:
        if not current_user.email_check:
            current_user.email_check = True
            if current_user.level == 1:
                current_user.level = 2
            db.session.commit()
    return redirect(url_for('personal'))


@app.route("/admin")
@moderator
def admin():
    users = User.query.order_by(User.apartment).filter(User.level <= current_user.level).all()
    return render_template('admin.html', all_users=users)


@app.route("/admin/user/<int:user_id>", methods=['GET', 'POST'])
@moderator
def edit_user(user_id):
    user = User.query.get(user_id)
    if user.level > current_user.level:
        return redirect(url_for('admin'))
    form = UserForm(apartment=user.apartment,
                    name=user.name,
                    lastname=user.lastname,
                    email=user.email,
                    phone=user.phone,
                    email_check=user.email_check,
                    level=user.level)
    if form.validate_on_submit():
        level = form.level.data
        if level > current_user.level:
            level = current_user.level
        user.level = level
        user.name = form.name.data
        user.lastname = form.lastname.data
        user.phone = format_phone(form.phone.data)
        user.apartment = form.apartment.data
        if current_user.level == 5:
            user.email = form.email.data
            user.email_check = form.email_check.data
        db.session.commit()
        return redirect(url_for('edit_user', user_id=user.id))
    return render_template('edit-user.html', form=form, user=user)


@app.route("/admin/user/<int:user_id>/delete")
@admin_only
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin'))


@app.route("/admin/user/<int:user_id>/note", methods=['GET', 'POST'])
@moderator
def note_user(user_id):
    form = MessageForm()
    user = User.query.get(user_id)
    if form.validate_on_submit():
        note = Notification(date=date_time(),
                            text=clean_html(form.text.data),
                            author_id=current_user.id,
                            recipient_id=user_id)
        db.session.add(note)
        db.session.commit()
        return redirect(url_for('admin'))
    return render_template('notification.html', user=user, form=form)


@app.route("/forgot", methods=['GET', 'POST'])
def forgot():
    form = EmailForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Этот email не зарегистрирован.', 'error')
            return redirect(url_for('login'))
        code = jwt.encode({'email': email, 'timestamp': int(datetime.now().timestamp())},
                          app.config.get('SECRET_KEY'), algorithm='HS256')
        content = f"<p><b>Для восстановления пароля перейдите по одноразовой ссылке:</b></p>" \
                  f"<a target='_blank' href='{request.url}/reset?code={code}'>" \
                  f"СОЗДАТЬ НОВЫЙ ПАРОЛЬ</a>"
        send_email(email, "Восстановление пароля для сайта Новосмоленская 2", content)
        flash('Ссылка для восстановления отправлена на ваш Email.')
        return redirect(url_for('forgot'))
    return render_template('forgot.html', form=form)


@app.route("/forgot/reset", methods=['GET', 'POST'])
def reset_pass():
    code = request.args.get('code')
    data = jwt.decode(code, app.config.get('SECRET_KEY'), algorithms=['HS256'])
    email = data.get('email')
    timestamp = data.get('timestamp')
    if timestamp + 300 > int(datetime.now().timestamp()):
        user = User.query.filter_by(email=email).first()
        form = NewPassForm()
        if form.validate_on_submit():
            if form.password.data != form.password2.data:
                flash('Пароли не совпадают!')
                return render_template('new-pass.html', form=form)
            user_hash = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=16)
            user.password = user_hash
            db.session.commit()
            login_user(user)
            return redirect(url_for('personal'))
        return render_template('new-pass.html', form=form)
    return redirect(url_for('get_all_posts'))


@app.route("/email/change", methods=['GET', 'POST'])
def change_email():
    form = EmailForm()
    if form.validate_on_submit() and current_user.is_authenticated:
        email = form.email.data
        if User.query.filter_by(email=email).first():
            flash('Этот email уже зарегистрирован.', 'error')
            return redirect(url_for('change_email'))
        current_user.email = email
        current_user.email_check = False
        if current_user.level == 2:
            current_user.level = 1
        db.session.commit()
        return redirect(url_for('personal'))
    return render_template('change-email.html', form=form)


@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static', 'img'),
                               'favicon.ico', mimetype='image/png')

# if __name__ == "__main__":
# app.run(host='0.0.0.0', port=1234)
