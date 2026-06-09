#!/bin/sh
set -e

echo "Aguardando banco de dados PostgreSQL..."
until pg_isready -h db -U mobat_user -d mobat_db; do
  echo "PostgreSQL ainda não está pronto - aguardando..."
  sleep 2
done
echo "PostgreSQL está pronto!"

cd /app

mkdir -p mobat_app/migrations
touch mobat_app/migrations/__init__.py

echo "Criando migrações para mobat_app..."
uv run python manage.py makemigrations mobat_app --noinput

echo "Aplicando migrações..."
uv run python manage.py migrate --noinput

echo "Carregando dados do SQLite..."
uv run python manage.py load_sqlite_data

echo "Iniciando servidor..."
uv run python manage.py runserver 0.0.0.0:8000