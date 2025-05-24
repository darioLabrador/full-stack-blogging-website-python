from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired

# Render form to create a post
class PostForm(FlaskForm):
    title = StringField(validators=[DataRequired()])
    body = TextAreaField(validators=[DataRequired()])
    submit = SubmitField()