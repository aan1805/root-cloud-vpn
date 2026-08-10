from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, TextAreaField, PasswordField
from wtforms.validators import DataRequired, Optional, NumberRange, IPAddress

class HaproxyServerForm(FlaskForm):
    name = StringField('Название', validators=[DataRequired()])
    ip = StringField('IP адрес', validators=[DataRequired(), IPAddress()])
    endpoint_domain = StringField(
        'Домен для конфигов',
        validators=[Optional()],
        description='Попадает в конфиги клиентов вместо IP — позволяет менять сервер без перевыпуска конфигов.'
    )
    ssh_port = IntegerField('SSH порт', validators=[DataRequired(), NumberRange(min=1, max=65535)], default=22)
    ssh_username = StringField('SSH пользователь', validators=[DataRequired()])
    ssh_key = TextAreaField('Приватный SSH ключ', validators=[DataRequired()])
    ssh_key_passphrase = PasswordField('Пароль от ключа (если есть)', validators=[Optional()])
    config_path = StringField('Путь к конфигу', default='/etc/haproxy/haproxy.cfg')
    stats_socket_path = StringField('Путь к stats socket', default='/var/run/haproxy.sock')
    stats_port = IntegerField('Порт статистики', default=8404)

class HaproxyBackendForm(FlaskForm):
    name = StringField('Имя бэкенда', validators=[DataRequired()])
    group_id = SelectField('Группа серверов', coerce=int, validators=[Optional()])
    protocol_type = SelectField('Протокол', choices=[
        ('awg', 'AmneziaWG'),
        ('xray', 'XRay Reality'),
        ('openvpn', 'OpenVPN')
    ], validators=[DataRequired()])
    mode = SelectField('Режим', choices=[
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
        ('http', 'HTTP')
    ], validators=[DataRequired()])
    balance_algorithm = SelectField('Алгоритм балансировки', choices=[
        ('roundrobin', 'Round Robin'),
        ('leastconn', 'Least Connections'),
        ('source', 'Source IP')
    ], validators=[DataRequired()])
    port = IntegerField('Порт', validators=[DataRequired(), NumberRange(min=1, max=65535)])