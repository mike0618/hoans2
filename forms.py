from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, IntegerField, TelField, DecimalField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField


# WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Заголовок", validators=[DataRequired()])
    subtitle = StringField("Коротко...", validators=[DataRequired()])
    img_url = StringField("Ссылка на картинку для новости", validators=[URL()])
    body = CKEditorField("Содержание", validators=[DataRequired()])
    submit = SubmitField("Опубликовать")


class RegisterForm(FlaskForm):
    apartment = IntegerField("Квартира", validators=[DataRequired()])
    lastname = StringField("Фамилия", validators=[DataRequired()])
    name = StringField("Имя", validators=[DataRequired()])
    phone = TelField("Телефон", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Пароль", validators=[DataRequired(), Length(8)])
    submit = SubmitField("Зарегистрироваться")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Пароль", validators=[DataRequired()])
    submit = SubmitField("Войти")


class CommentForm(FlaskForm):
    text = CKEditorField("Комментарий", validators=[DataRequired()])
    submit = SubmitField("Комментировать")


class MessageForm(FlaskForm):
    text = CKEditorField("Сообщение", validators=[DataRequired()])
    submit = SubmitField("Отправить")


class MetersForm(FlaskForm):
    cold_water = DecimalField("Холодная вода", validators=[DataRequired()])
    hot_water = DecimalField("Горячая вода", validators=[DataRequired()])
    submit = SubmitField("Передать")


class UserForm(RegisterForm):
    password = None
    email_check = BooleanField("EMAIL подтверждён")
    level = IntegerField("Уровень доступа", validators=[DataRequired()])
    submit = SubmitField('Применить')


class EmailForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField('Отправить')


class NewPassForm(FlaskForm):
    password = PasswordField("Новый пароль", validators=[DataRequired(), Length(8)])
    password2 = PasswordField("Повторите пароль", validators=[DataRequired(), Length(8)])
    submit = SubmitField('Сохранить')
