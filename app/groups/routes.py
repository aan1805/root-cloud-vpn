from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required
from app.groups import bp
from app.groups.forms import GroupForm
from app.models import ServerGroup, Server, HaproxyServer
from app.extensions import db


def _populate_form(form):
    haproxy_servers = HaproxyServer.query.order_by(HaproxyServer.name).all()
    form.reality_haproxy_server_id.choices = [(0, '— не выбрано —')] + [
        (h.id, h.name) for h in haproxy_servers
    ]


@bp.route('/')
@login_required
def index():
    groups = ServerGroup.query.all()
    return render_template('groups/index.html', groups=groups)


@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = GroupForm()
    _populate_form(form)
    if form.validate_on_submit():
        group = ServerGroup(name=form.name.data, description=form.description.data,
                            is_public=form.is_public.data)
        db.session.add(group)
        db.session.commit()

        if form.reality_enabled.data and form.reality_haproxy_server_id.data:
            from app.tasks import enable_group_reality_task
            enable_group_reality_task.delay(
                group.id,
                form.reality_port.data or 4443,
                form.reality_sni.data or 'www.microsoft.com',
                form.reality_haproxy_server_id.data
            )
            flash('Группа создана. Reality настраивается (~1 мин).', 'info')
        else:
            flash(f'Группа {group.name} создана', 'success')

        return redirect(url_for('groups.index'))
    return render_template('groups/form.html', form=form, title="Создать группу", group=None)


@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    group = ServerGroup.query.get_or_404(id)
    form = GroupForm(obj=group)
    _populate_form(form)

    # WTForms coerce=int не обрабатывает None — подставляем 0
    if request.method == 'GET' and group.reality_haproxy_server_id is None:
        form.reality_haproxy_server_id.data = 0

    if form.validate_on_submit():
        group.name = form.name.data
        group.description = form.description.data
        group.is_public = form.is_public.data
        db.session.commit()

        want_reality = form.reality_enabled.data and bool(form.reality_haproxy_server_id.data)

        if want_reality:
            haproxy_id = form.reality_haproxy_server_id.data
            port = form.reality_port.data or 4443
            sni = form.reality_sni.data or 'yandex.ru'

            settings_changed = (
                not group.reality_enabled
                or group.reality_haproxy_server_id != haproxy_id
                or group.reality_port != port
                or group.reality_sni != sni
            )
            if settings_changed:
                from app.tasks import enable_group_reality_task
                enable_group_reality_task.delay(group.id, port, sni, haproxy_id)
                flash('Reality настраивается (~1 мин).', 'info')
        elif group.reality_enabled:
            from app.tasks import disable_group_reality_task
            disable_group_reality_task.delay(group.id)
            flash('Reality отключается.', 'info')

        flash('Группа обновлена', 'success')
        return redirect(url_for('groups.index'))

    return render_template('groups/form.html', form=form, title="Редактировать группу", group=group)


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
