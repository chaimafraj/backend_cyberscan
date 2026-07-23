import os
from pathlib import Path
from datetime import timedelta

from corsheaders.defaults import default_headers

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-$m*(*d*!srk)(!y3v_%anjl@0j3%(0(^d$pj#$@bepb9hnzzva'

DEBUG = True

# localhost + testserver (Django test client / APIClient)
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]', 'testserver']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'scanner',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'cyberapp_db',
        'USER': 'postgres',
        'PASSWORD': 'postgres',
        'HOST': '127.0.0.1',
        'PORT': '5432',
        'OPTIONS': {
            'client_encoding': 'UTF8',
        },
    }
}

AUTH_USER_MODEL = 'scanner.User'  # ← IMPORTANT

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(days=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': False,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# --- Médias / rapports PDF CyberScan ---
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'
REPORTS_DIR = MEDIA_ROOT / 'rapports'

# URLs publiques pour les liens dans les emails de rapport
CYBERSCAN_SITE_URL = os.environ.get('CYBERSCAN_SITE_URL', 'http://localhost:4200')
CYBERSCAN_API_URL = os.environ.get('CYBERSCAN_API_URL', 'http://localhost:8000')

# Frontend Angular autorise a appeler l'API Django en developpement.
# Une origine ne contient pas de slash final.
CORS_ALLOWED_ORIGINS = [
    'http://localhost:4200',
    'http://127.0.0.1:4200',
]

# Necessaire pour les requetes non sures authentifiees par cookie/CSRF.
CSRF_TRUSTED_ORIGINS = [
    'http://localhost:4200',
    'http://127.0.0.1:4200',
]

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = [
    *default_headers,
    'sec-ch-ua',
    'sec-ch-ua-mobile',
    'sec-ch-ua-platform',
]
CORS_ALLOW_METHODS = [
    'DELETE',
    'GET',
    'OPTIONS',
    'PATCH',
    'POST',
    'PUT',
]

# --- Logging : affiche les logs du scanner (dont OWASP ZAP) dans la console ---
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{asctime}] {levelname} {name}: {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'scanner': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'farajchaima8@gmail.com'
EMAIL_HOST_PASSWORD = 'epjynxdelvnccfcx'
DEFAULT_FROM_EMAIL = 'CyberScan <farajchaima8@gmail.com>'