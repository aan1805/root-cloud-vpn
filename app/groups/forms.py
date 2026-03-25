from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, BooleanField, IntegerField, SelectField
from wtforms.validators import DataRequired, Length, Optional, NumberRange


class GroupForm(FlaskForm):
    name = StringField('Название группы (например, "RU-Servers")', validators=[DataRequired(), Length(min=2, max=64)])
    description = TextAreaField('Описание', validators=[Length(max=255)])
    is_public = BooleanField('Публичная группа', default=True)

    # XRay Reality per-group (обход DPI)
    reality_enabled = BooleanField('Включить XRay Reality (обход цензуры)')
    reality_port = IntegerField('Reality порт', default=4443,
                                validators=[Optional(), NumberRange(min=1024, max=65535)])
    reality_sni = StringField('SNI домен', default='www.microsoft.com')
    reality_haproxy_server_id = SelectField('HAProxy сервер', coerce=int, validators=[Optional()])

    submit = SubmitField('Сохранить группу')
