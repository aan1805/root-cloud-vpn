#!/bin/bash
set -e

if [ "$1" = "worker" ]; then
    exec celery -A app.celery_app.celery worker --loglevel=info
elif [ "$1" = "beat" ]; then
    exec celery -A app.celery_app.celery beat --loglevel=info
else
    exec "$@"
fi