from celery.schedules import crontab

from app import celery

celery.conf.beat_schedule = {
    'collect-stats-every-hour': {
        'task': 'app.tasks.collect_all_stats',
        'schedule': crontab(minute=0),  # каждый час в 0 минут
    },
    'check-limits-every-15-minutes': {
        'task': 'app.tasks.check_all_limits',
        'schedule': crontab(minute='*/15'),  # каждые 15 минут
    },
    'check-servers-status-every-5-minutes': {
        'task': 'app.tasks.check_all_servers_status',
        'schedule': crontab(minute='*/5'),  # каждые 5 минут
    },
    'cleanup-deleted-oidc-users-nightly': {
        'task': 'app.tasks.cleanup_deleted_oidc_users',
        'schedule': crontab(hour=3, minute=0),  # каждую ночь в 3:00
    },
}