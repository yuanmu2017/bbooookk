import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'hard to guess string'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = False


class DevelopmentConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}


from flask import Flask
app = Flask(__name__)
config_name = os.getenv('FLASK_CONFIG') or 'default'
app.config.from_object(config[config_name])

from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'
login_manager.login_message = u'请先登陆，登录成功后才可访问这个网页'


from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import Email, DataRequired, Length
class LoginForm(FlaskForm):
    email = StringField(u'邮箱：', validators=[DataRequired(), Email(), Length(1, 64)])
    password = PasswordField(u'密码：', validators=[DataRequired()])
    keep_in = BooleanField(u'记住我')
    submit = SubmitField('登录')


from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True)
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % self.email

    @staticmethod
    def init_user(email, password):
        user = User(email=email, password=password)
        db.session.add(user)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Data(db.Model):
    __tablename__ = 'datas'
    id = db.Column(db.Integer, primary_key=True)
    count = db.Column(db.Integer, default=0)
    name = db.Column(db.String(28), unique=True)

    @staticmethod
    def init_data(count=0, name="total_access"):
        data = Data(count=count, name=name)
        db.session.add(data)
        db.session.commit()



from flask import Blueprint
from flask import render_template, flash, redirect, url_for, request
from flask_login import login_user, login_required, current_user, logout_user
auth = Blueprint('auth', __name__)
@auth.before_app_request
def before_request():
    if not current_user.is_authenticated and request.endpoint[:5] != 'auth.' and request.endpoint != 'static':
        data = Data.query.filter_by(name='total_access').first()
        data.count += 1
        db.session.add(data)
        db.session.commit()


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.keep_in.data)
            flash(u'登录成功')
            return redirect(request.args.get('next') or url_for('auth.login_state'))
        flash(u'用户不存在或者密码错误')
    return render_template('auth/login.html', form=form)


@auth.route('/login-state')
@login_required
def login_state():
    data = Data.query.filter_by(name='total_access').first()
    return render_template('auth/login_state.html', data=data)


@auth.route('/logout')
def logout():
    if not current_user.is_authenticated:
        return redirect(url_for('main.books_by_tag', tag='文学'))
    logout_user()
    flash(u'您已退出登录')
    return redirect(url_for('main.books_by_tag', tag='文学'))

app.register_blueprint(auth, url_prefix='/auth')



error = Blueprint('error', __name__)
@error.app_errorhandler(500)
def internal_server_error(e):
    return render_template('error/500.html'), 500

@error.app_errorhandler(404)
def not_found_error(e):
    return render_template('error/404.html'), 404

@error.app_errorhandler(403)
def has_no_permission_error(e):
    return render_template('error/403.html'), 403

app.register_blueprint(error, url_prefix='/error')


class BookForm(FlaskForm):
    name = StringField(u'书名', validators=[DataRequired(), Length(1, 128)])
    author = StringField(u'作者', validators=[DataRequired(), Length(1, 128)])
    intro = StringField(u'一句话介绍', validators=[DataRequired(), Length(1, 256)])
    tag = StringField(u'主分类', validators=[DataRequired(), Length(1, 32)])
    sub_tag = StringField('次分类', validators=[DataRequired(), Length(1, 32)])
    download_link = StringField(u'下载链接', validators=[DataRequired(), Length(1, 256)])
    spare_download_link = StringField(u'备用下载链接', validators=[DataRequired(), Length(1, 256)])
    submit = SubmitField(u'提交')


from wtforms import TextAreaField
class InstagramForm(FlaskForm):
    tag = StringField(u'分类', validators=[DataRequired(), Length(1, 32)])
    user_id = StringField(u'用户ID', validators=[DataRequired(), Length(1, 64)])
    intro = StringField(u'一句话介绍', validators=[DataRequired(), Length(1, 128)])
    title = StringField(u'标题', validators=[DataRequired(), Length(1, 128)])
    body = TextAreaField(u'文章主体', validators=[DataRequired()])
    download_link = StringField(u'下载链接', validators=[DataRequired(), Length(1, 256)])
    spare_download_link = StringField(u'备用下载链接', validators=[DataRequired(), Length(1, 256)])
    submit = SubmitField(u'提交')


from datetime import datetime
class Book(db.Model):
    __tablename__ = 'books'
    id = db.Column(db.Integer, primary_key=True)
    cover_image_thumb = db.Column(db.String(128))
    name = db.Column(db.String(128))
    author = db.Column(db.String(128))
    intro = db.Column(db.String(256))
    tag = db.Column(db.String(32), index=True)
    sub_tag = db.Column(db.String(32), index=True)
    cover_image = db.Column(db.String(128))
    mulu_image = db.Column(db.String(128))
    yangzhang_image = db.Column(db.String(128))
    download_link = db.Column(db.String(256))
    spare_download_link = db.Column(db.String(256))
    download_count = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime(), default=datetime.utcnow)

class Instagram(db.Model):
    __tablename__ = 'instagrams'
    id = db.Column(db.Integer, primary_key=True)
    tag = db.Column(db.String(32), index=True)
    user_id = db.Column(db.String(64))
    cover_image = db.Column(db.String(128))
    intro = db.Column(db.String(128))
    title = db.Column(db.String(128))
    body = db.Column(db.Text())
    download_link = db.Column(db.String(256))
    spare_download_link = db.Column(db.String(256))
    download_count = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime(), default=datetime.utcnow)


main = Blueprint('main', __name__)
@main.route('/')
def index():
    return redirect(url_for('main.books_by_tag', tag='文学'))


@login_required
@main.route('/post_book', methods=['GET', 'POST'])
def post_book():
    form = BookForm()
    if form.validate_on_submit():
        book = Book(cover_image_thumb='/static/books/'+form.tag.data+'/'+form.name.data+'/封面_缩略图.png',
                    name=form.name.data,
                    author=form.author.data,
                    intro=form.intro.data,
                    tag=form.tag.data,
                    sub_tag=form.sub_tag.data,
                    cover_image='/static/books/'+form.tag.data+'/'+form.name.data+'/封面.png',
                    mulu_image='/static/books/'+form.tag.data+'/'+form.name.data+'/目录.png',
                    yangzhang_image='/static/books/'+form.tag.data+'/'+form.name.data+'/样章.png',
                    download_link=form.download_link.data,
                    spare_download_link=form.spare_download_link.data)
        db.session.add(book)
        db.session.commit()
        return redirect(url_for('main.book_detail', book_id=book.id))
    return render_template('main/post_book.html', form=form)


@main.route('/books/tag/<tag>')
def books_by_tag(tag):
    page = request.args.get('page', 1, type=int)
    pagination = Book.query.filter_by(tag=tag).order_by(Book.download_count.desc()).paginate(page, per_page=10, error_out=False)
    books = pagination.items

    items = []
    for i, book in enumerate(books):
        if i % 2 == 0:
            item = []
            items.append(item)
        item.append(book)
    return render_template('main/books_by_tag.html', items=items, pagination=pagination, tag=tag)


@main.route('/books/subtag/<subtag>')
def books_by_subtag(subtag):
    page = request.args.get('page', 1, type=int)
    pagination = Book.query.filter_by(sub_tag=subtag).order_by(Book.download_count.desc()).paginate(page, per_page=10, error_out=False)
    books = pagination.items

    items = []
    for i, book in enumerate(books):
        if i % 2 == 0:
            item = []
            items.append(item)
        item.append(book)

    return render_template('main/books_by_sub_tag.html', items=items, pagination=pagination, subtag=subtag)

@main.route('/books/author/<author>')
def books_by_author(author):
    page = request.args.get('page', 1, type=int)
    pagination = Book.query.filter_by(author=author).order_by(Book.download_count.desc()).paginate(page, per_page=10,
                                                                                                    error_out=False)
    books = pagination.items
    items = []
    for i, book in enumerate(books):
        if i % 2 == 0:
            item = []
            items.append(item)
        item.append(book)

    return render_template('main/books_by_author.html', items=items, pagination=pagination, author=author)



@main.route('/books/download/<int:book_id>')
def book_download(book_id):
    book = Book.query.get_or_404(book_id)
    book.download_count += 1
    return redirect(book.download_link)


@main.route('/books/download-spare/<int:book_id>')
def spare_book_download(book_id):
    book = Book.query.get_or_404(book_id)
    book.download_count += 1
    return redirect(book.spare_download_link)


@login_required
@main.route('/edit_book/<int:book_id>', methods=['GET', 'POST'])
def edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    form = BookForm()
    if form.validate_on_submit():
        book.cover_image_thumb = '/static/books/'+form.tag.data+'/'+form.name.data+'/封面_缩略图.png'
        book.name = form.name.data
        book.author = form.author.data
        book.intro = form.intro.data
        book.tag = form.tag.data
        book.sub_tag = form.sub_tag.data
        book.cover_image = '/static/books/'+form.tag.data+'/'+form.name.data+'/封面.png'
        book.mulu_image = '/static/books/'+form.tag.data+'/'+form.name.data+'/目录.png'
        book.yangzhang_image = '/static/books/'+form.tag.data+'/'+form.name.data+'/样章.png'
        book.download_link = form.download_link.data
        book.spare_download_link = form.spare_download_link.data
        db.session.add(book)
        db.session.commit()
        flash(u'图书修改成功')
        return redirect(url_for('main.book_detail', book_id=book.id))
    form.name.data = book.name
    form.author.data = book.author
    form.intro.data = book.intro
    form.tag.data = book.tag
    form.sub_tag.data = book.sub_tag
    form.download_link.data = book.download_link
    form.spare_download_link.data = book.spare_download_link
    return render_template('main/edit_book.html', form=form)


@login_required
@main.route('/delete-book/<int:book_id>')
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    flash(u'删除成功')
    return redirect(url_for('main.books_by_tag', tag=book.tag))


@main.route('/book-detail/<int:book_id>')
def book_detail(book_id):
    book = Book.query.get_or_404(book_id)
    return render_template('main/book_detail.html', book=book)


@main.route('/post-instagrams',  methods=['GET', 'POST'])
def post_instagram():
    form = InstagramForm()
    if form.validate_on_submit():
        instagram = Instagram(tag=form.tag.data,
                              user_id=form.user_id.data,
                              cover_image='/static/instagrams/'+form.tag.data+'/'+form.user_id.data+'/cover.png',
                              intro=form.intro.data,
                              title=form.title.data,
                              body=form.body.data,
                              download_link=form.download_link.data,
                              spare_download_link=form.spare_download_link.data)
        db.session.add(instagram)
        db.session.commit()
        return redirect(url_for('main.instagram_detail', instagram_id=instagram.id))
    return render_template('main/post_instagram.html', form=form)


@main.route('/instagrams-detail/<int:instagram_id>')
def instagram_detail(instagram_id):
    instagram = Instagram.query.get_or_404(instagram_id)
    return render_template('main/instagram_detail.html', instagram=instagram)


@main.route('/instagrams_by_tag/<tag>')
def instagrams_by_tag(tag):
    page = request.args.get('page', 1, type=int)
    pagination = Instagram.query.filter_by(tag=tag).order_by(Instagram.download_count.desc()).paginate(page,
                                                                                                       per_page=10,
                                                                                                       error_out=False)
    instagrams = pagination.items
    return render_template('main/instagrams_by_tag.html', instagrams=instagrams, pagination=pagination, tag=tag)


@main.route('/instagrams/download/<int:instagram_id>')
def instagram_download(instagram_id):
    instagram = Instagram.query.get_or_404(instagram_id)
    instagram.download_count += 1
    return redirect(instagram.download_link)

@main.route('/instagrams/download-spare/<int:instagram_id>')
def spare_instagram_download(instagram_id):
    instagram = Instagram.query.get_or_404(instagram_id)
    instagram.download_count += 1
    return redirect(instagram.spare_download_link)


@login_required
@main.route('/edit_instagram/<int:instagram_id>', methods=['GET', 'POST'])
def edit_instagram(instagram_id):
    instagram = Instagram.query.get_or_404(instagram_id)
    form = InstagramForm()
    if form.validate_on_submit():
        instagram.tag = form.tag.data
        instagram.user_id = form.user_id.data
        instagram.cover_image = '/static/instagrams/'+form.tag.data+'/'+form.user_id.data+'/cover.png'
        instagram.intro = form.intro.data
        instagram.title = form.title.data
        instagram.body = form.body.data
        instagram.download_link = form.download_link.data
        instagram.spare_download_link = form.spare_download_link.data
        db.session.add(instagram)
        db.session.commit()
        flash(u'Instagram修改成功')
        return redirect(url_for('main.instagram_detail', instagram_id=instagram.id))
    form.tag.data = instagram.tag
    form.user_id.data = instagram.user_id
    form.intro.data = instagram.intro
    form.title.data = instagram.title
    form.body.data = instagram.body
    form.download_link.data = instagram.download_link
    form.spare_download_link.data = instagram.spare_download_link
    return render_template('main/edit_instagram.html', form=form)


@login_required
@main.route('/delete-instagrams/<int:instagram_id>')
def delete_instagram(instagram_id):
    instagram = Instagram.query.get_or_404(instagram_id)
    db.session.delete(instagram)
    flash(u'删除成功')
    return redirect(url_for('main.instagrams_by_tag', tag=instagram.tag))
app.register_blueprint(main)


from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand
manager = Manager(app)
migrate = Migrate(app, db)


def make_shell_context():
    return dict(app=app, db=db, User=User,  Data=Data)
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


if __name__ == '__main__':
    manager.run()
