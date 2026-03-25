from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length

class GroupForm(FlaskForm):
    name = StringField('Название группы (например, "RU-Servers")', validators=[DataRequired(), Length(min=2, max=64)])
    description = TextAreaField('Описание', validators=[Length(max=255)])
    is_public = BooleanField('Публичная группа', default=True)
    submit = SubmitField('Сохранить группу')
