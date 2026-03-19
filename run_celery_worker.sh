#!/bin/bash
celery -A app.celery_app.celery worker --loglevel=info