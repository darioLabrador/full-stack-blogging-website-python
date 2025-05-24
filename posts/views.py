from cryptography.fernet import Fernet
from flask import Blueprint, render_template, flash, url_for, redirect, request
from flask_login import current_user, login_required
from config import db, Post, roles_required, logger
from posts.forms import PostForm
from sqlalchemy import desc

# Set up blueprint
posts_bp = Blueprint('posts', __name__, template_folder='templates')

# Displays all created posts
@posts_bp.route('/posts')
@roles_required('end_user')
@login_required
def posts():
    all_posts = Post.query.order_by(desc('id')).all()
    return render_template('posts/posts.html', posts=all_posts)

# Creates a post
@posts_bp.route('/create', methods=('GET', 'POST'))
@roles_required('end_user')
@login_required
def create():

    form = PostForm()

    if form.validate_on_submit():

        # Key for post encryption
        key = current_user.generate_key()
        cipher = Fernet(key)

        # Assign values to create new post
        new_post = Post(userid=current_user.get_id(),
                        title=cipher.encrypt(form.title.data.encode()),
                        body=cipher.encrypt(form.body.data.encode()))
        db.session.add(new_post)
        db.session.commit()

        # Display log
        logger.warning('[User Email:{}, User Role:{}, Post ID:{}, User IP Address:{}] Created post'.format(
            current_user.email, current_user.role, new_post.user.get_id(), request.remote_addr))

        flash('Post created', category='success')
        return redirect(url_for('posts.posts'))

    return render_template('posts/create.html', form=form)

# Updates an existing post
@posts_bp.route('/<int:id>/update', methods=('GET', 'POST'))
@roles_required('end_user')
@login_required
def update(id):

    # Find post to be updated
    post_to_update = Post.query.filter_by(id=id).first()
    if not post_to_update:
        return redirect(url_for('posts.posts'))

    form = PostForm()

    # Key for encryption
    key = current_user.generate_key()
    cipher = Fernet(key)

    # Check if current user is updating other user's post
    if current_user.get_id() != post_to_update.user.get_id():
        flash('You\'re not allowed to update other user\'s posts.', category='info')
        return redirect(url_for('posts.posts'))

    if form.validate_on_submit():

        # Assign values to create new post
        post_to_update.update(userid=current_user.get_id(),
                              title=cipher.encrypt(form.title.data.encode()),
                              body=cipher.encrypt(form.body.data.encode()))
        form.title.data = post_to_update.title
        form.body.data = post_to_update.body

        db.session.commit()

        flash('Post updated', category='success')

        # Display log
        logger.warning(
            '[User Email:{}, User Role:{}, Post ID:{}, Post Author\'s Email:{}, User IP Address:{} ] Updated post'.format(
                current_user.email, current_user.role, post_to_update.user.id, post_to_update.user.email, request.remote_addr))

        return redirect(url_for('posts.posts'))
    return render_template('posts/update.html', form=form)

# Delete post
@posts_bp.route('/<int:id>/delete')
@roles_required('end_user')
@login_required
def delete(id):

    post_to_delete = Post.query.filter_by(id=id).first()

    # Check if current user is deleting other user's post
    if current_user.get_id() != post_to_delete.user.get_id():
        flash('You\'re not allowed to delete other user\'s posts.', category='info')
        return redirect(url_for('posts.posts'))

    # Display log
    logger.warning('[User Email:{}, User Role:{}, Post ID:{}, Post Author\'s Email:{}, User IP Address:{} ] Deleted post'.format(
        current_user.email, current_user.role, post_to_delete.user.id, post_to_delete.user.email, request.remote_addr))

    # Delete post
    Post.query.filter_by(id=id).delete()
    db.session.commit()

    flash('Post deleted', category='success')
    return redirect(url_for('posts.posts'))

