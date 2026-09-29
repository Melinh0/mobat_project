import os
from pathlib import Path

from mobat_project.env import (
    load_env,
    env_bool,
    env_float,
    env_int,
    env_list,
    env_str,
)

BASE_DIR = Path(__file__).resolve().parent.parent

load_env(BASE_DIR / '.env')

SECRET_KEY = env_str('SECRET_KEY', os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-xxxxxxxxxxxx'))
DEBUG = env_bool('DJANGO_DEBUG', True)

ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'drf_yasg',
    'mobat_app',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'mobat_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'mobat_project.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'pt-br'
TIME_ZONE = 'America/Sao_Paulo'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

OLLAMA_HOST = env_str('OLLAMA_HOST', 'https://ollama.com').rstrip('/')
OLLAMA_API_KEYS = env_list('OLLAMA_API_KEY')
OLLAMA_AVAILABLE_MODELS = env_list('OLLAMA_AVAILABLE_MODELS', 'gemma4:cloud')
OLLAMA_VISION_MODELS = env_list('OLLAMA_VISION_MODELS')
OLLAMA_DEFAULT_MODEL = env_str('DEFAULT_MODEL', env_str('OLLAMA_DEFAULT_MODEL', 'gemma4:cloud'))

OLLAMA_MAX_TOKENS = env_int('OLLAMA_MAX_TOKENS', 16000)
OLLAMA_REQUEST_TIMEOUT = env_int('OLLAMA_REQUEST_TIMEOUT', 600)
OLLAMA_CONNECT_TIMEOUT = env_int('OLLAMA_CONNECT_TIMEOUT', 15)
OLLAMA_MAX_RETRIES = env_int('OLLAMA_MAX_RETRIES', 3)

OLLAMA_MAX_CONCURRENT_REQUESTS = env_int('OLLAMA_MAX_CONCURRENT_REQUESTS', 4)
OLLAMA_MIN_REQUEST_INTERVAL = env_float('OLLAMA_MIN_REQUEST_INTERVAL', 0.5)
OLLAMA_RATE_LIMIT_BACKOFF_BASE = env_float('OLLAMA_RATE_LIMIT_BACKOFF_BASE', 5)
OLLAMA_RATE_LIMIT_MAX_BACKOFF = env_float('OLLAMA_RATE_LIMIT_MAX_BACKOFF', 120)

ANALYZE_TEMPERATURE_WITH_RAG = env_float('ANALYZE_TEMPERATURE_WITH_RAG', 0.3)
ANALYZE_TEMPERATURE_WITHOUT_RAG = env_float('ANALYZE_TEMPERATURE_WITHOUT_RAG', 0.0)
GEN_TEMPERATURE_GENERIC = env_float('GEN_TEMPERATURE_GENERIC', 0.0)

RAG_SERVICE_URL = env_str('RAG_SERVICE_URL', '')
RAG_SIMILARITY_THRESHOLD = env_float('RAG_SIMILARITY_THRESHOLD', 0.72)
RAG_TFIDF_THRESHOLD = env_float('RAG_TFIDF_THRESHOLD', 0.15)
RAG_N_RESULTS = env_int('RAG_N_RESULTS', 12)
RAG_WORD_MIN_DF = env_int('RAG_WORD_MIN_DF', 0)
RAG_CHAR_MIN_DF = env_int('RAG_CHAR_MIN_DF', 0)
INDEX_CHUNK_TARGET_SIZE = env_int('INDEX_CHUNK_TARGET_SIZE', 500)
INDEX_CHUNK_OVERLAP = env_int('INDEX_CHUNK_OVERLAP', 80)
INDEX_MIN_ROWS_PER_CHUNK = env_int('INDEX_MIN_ROWS_PER_CHUNK', 10)

CHATBOT_HISTORY_LIMIT = env_int('CHATBOT_HISTORY_LIMIT', 8)
CHATBOT_MAX_QUESTION_LENGTH = env_int('CHATBOT_MAX_QUESTION_LENGTH', 2000)
CHATBOT_ENABLED = env_bool('CHATBOT_ENABLED', True)
CHATBOT_ENABLE_ANALYSIS = env_bool('CHATBOT_ENABLE_ANALYSIS', True)
CHATBOT_ANALYSIS_TIMEOUT = env_float('CHATBOT_ANALYSIS_TIMEOUT', 10.0)

MIDDLEWARE += [
    'mobat_app.middleware.ChatbotWidgetMiddleware',
]
