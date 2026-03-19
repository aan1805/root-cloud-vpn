from flask_wtf import FlaskForm
from wtforms import SelectField, IntegerField, SubmitField, StringField
from wtforms.validators import DataRequired, NumberRange, Optional


class ProtocolInstallForm(FlaskForm):
    protocol_type = SelectField('Протокол', choices=[
        ('awg', 'AmneziaWG (WireGuard)'),
        ('xray', 'XRay Reality')
    ], validators=[DataRequired()])

    port = IntegerField('Порт', validators=[DataRequired(), NumberRange(min=1, max=65535)], default=51820)

    # Дополнительные параметры для XRay
    xray_server_name = StringField('Server Name (для Reality)', validators=[Optional()],
                                   default='www.microsoft.com')
    xray_short_id = StringField('Short ID', validators=[Optional()], default='6ba85179e30d4fc2')

    # Для OpenVPN
    openvpn_proto = SelectField('Протокол OpenVPN', choices=[('udp', 'UDP'), ('tcp', 'TCP')],
                                validators=[Optional()], default='udp')

    submit = SubmitField('Установить')