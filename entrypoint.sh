#!/bin/sh
set -e

cd /app
uv run python manage.py migrate --noinput
uv run python manage.py runserver 0.0.0.0:8000