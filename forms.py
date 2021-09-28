from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, HiddenField
from wtforms.validators import DataRequired, URL, Length, Email, InputRequired, EqualTo
from flask_ckeditor import CKEditorField


##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


##REGISTER FORM
class RegisterForm(FlaskForm):
    email = StringField('Email id', validators=[DataRequired(), Email(message='Please insert correct email address',
                                                                      check_deliverability=True)])
    name = StringField('Name', validators=[DataRequired('Please Enter Your Name')])
    password = PasswordField('Password', validators=[DataRequired('Please Enter Your Password'),
                                                     EqualTo('confirm', message='Password  must match')])
    confirm = PasswordField("Re-Enter Password", validators=[DataRequired('Please confirm your Password')])
    submit = SubmitField('Sign Me UP')


##Login Form
class LoginForm(FlaskForm):
    email = StringField('Email id', validators=[DataRequired(), Email(message='Please insert correct email address',
                                                                      check_deliverability=True)])
    password = PasswordField('Password', validators=[DataRequired('Please Enter Your Password')])
    submit = SubmitField('Let Me In')


##COMMENT FORM
class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[InputRequired(), Length(min=5, max=500,
                                                                          message='Please enter your comment in 5 to '
                                                                                  '500 characters')])
    submit = SubmitField("comment")