from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, IntegerField, DateTimeField, SubmitField
from wtforms.validators import DataRequired, Email, Optional, NumberRange
from wtforms.widgets import NumberInput


class ClientForm(FlaskForm):
    name = StringField('Имя клиента', validators=[DataRequired()])
    email = StringField('Email', validators=[Optional(), Email()])

    # Выбор: либо конкретный сервер, либо группа
    selection_type = SelectField('Тип подключения', choices=[('server', 'Конкретный сервер'), ('group', 'Группа серверов (HAProxy)')], default='server')

    server_id = SelectField('Сервер', coerce=int, validators=[Optional()])
    protocol_id = SelectField('Протокол', coerce=int, validators=[Optional()])

    group_id = SelectField('Группа серверов', coerce=int, validators=[Optional()])
    protocol_type = SelectField('Тип протокола (для группы)', choices=[('awg', 'AmneziaWG'), ('xray', 'XRay Reality')], validators=[Optional()])

    traffic_limit = IntegerField('Лимит трафика (ГБ)', validators=[Optional(), NumberRange(min=0)],
                                 default=0, widget=NumberInput())
    expiry_date = DateTimeField('Срок действия (YYYY-MM-DD HH:MM)', format='%Y-%m-%d %H:%M', validators=[Optional()])

    submit = SubmitField('Сохранить клиента')