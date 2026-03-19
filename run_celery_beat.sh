#!/bin/bash
celery -A app.celery_app.celery beat --loglevel=info