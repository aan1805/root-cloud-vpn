from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, TextAreaField, SubmitField, SelectField, BooleanField
from wtforms.validators import DataRequired, IPAddress, NumberRange, Optional

class ServerForm(FlaskForm):
    name = StringField('Название сервера', validators=[DataRequired()])
    group_id = SelectField('Группа серверов', coerce=int, validators=[Optional()])
    ip = StringField('IP-адрес', validators=[DataRequired(), IPAddress()])
    endpoint_domain = StringField(
        'Домен для конфигов',
        validators=[Optional()],
        description='Например de1.example.com. Попадает в конфиги клиентов вместо IP — '
                    'при смене сервера достаточно переставить A-запись, старые конфиги продолжат работать.'
    )
    ssh_port = IntegerField('SSH порт', validators=[DataRequired(), NumberRange(min=1, max=65535)], default=22)
    ssh_username = StringField('SSH пользователь', validators=[DataRequired()])
    ssh_key = TextAreaField('Приватный SSH ключ', validators=[DataRequired()], description='Начиная с "-----BEGIN..."')
    ssh_key_passphrase = PasswordField('Пароль от ключа (если есть)', validators=[Optional()])
    is_public = BooleanField('Публичный сервер', default=True)
    submit = SubmitField('Сохранить')