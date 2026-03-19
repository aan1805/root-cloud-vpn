from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required
from app.groups import bp
from app.groups.forms import GroupForm
from app.models import ServerGroup, Server
from app.extensions import db

@bp.route('/')
@login_required
def index():
    groups = ServerGroup.query.all()
    return render_template('groups/index.html', groups=groups)

@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = GroupForm()
    if form.validate_on_submit():
        group = ServerGroup(name=form.name.data, description=form.description.data)
        db.session.add(group)
        db.session.commit()
        flash(f'Группа {group.name} создана', 'success')
        return redirect(url_for('groups.index'))
    return render_template('groups/form.html', form=form, title="Создать группу")

@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    group = ServerGroup.query.get_or_404(id)
    form = GroupForm(obj=group)
    if form.validate_on_submit():
        group.name = form.name.data
        group.description = form.description.data
        db.session.commit()
        flash('Группа обновлена', 'success')
        return redirect(url_for('groups.index'))
    return render_template('groups/form.html', form=form, title="Редактировать группу")

@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    group = ServerGroup.query.get_or_404(id)
    if group.servers or group.clients:
        flash('Нельзя удалить группу, в которой есть серверы или клиенты', 'danger')
    else:
        db.session.delete(group)
        db.session.commit()
        flash('Группа удалена', 'success')
    return redirect(url_for('groups.index'))
