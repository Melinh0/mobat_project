from __future__ import annotations

import logging

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.middleware.csrf import get_token
from django.template.loader import render_to_string
from django.urls import reverse

logger = logging.getLogger(__name__)

MARKER = b'mobat-chatbot-root'
SKIP_PREFIXES = ('/admin/', '/static/', '/__debug__/')


class ChatbotWidgetMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        try:
            self._inject(request, response)
        except Exception:  # noqa: BLE001
            logger.exception('Falha ao injetar o widget do chatbot')
        return response

    def _should_inject(self, request: HttpRequest, response: HttpResponse) -> bool:
        if not getattr(settings, 'CHATBOT_ENABLED', True):
            return False
        if request.method != 'GET':
            return False
        if request.path.startswith(SKIP_PREFIXES):
            return False
        if response.status_code != 200 or getattr(response, 'streaming', False):
            return False
        if response.has_header('Content-Disposition'):
            return False
        if 'text/html' not in response.get('Content-Type', ''):
            return False
        return True

    def _inject(self, request: HttpRequest, response: HttpResponse) -> None:
        if not self._should_inject(request, response):
            return

        content = response.content
        if MARKER in content:
            return

        from .rag.datasets import dataset_from_session

        dataset = dataset_from_session(request.session)
        config = {
            'askUrl': reverse('chatbot_ask'),
            'statusUrl': reverse('chatbot_status'),
            'csrfToken': get_token(request),
            'datasetKey': dataset.key,
            'datasetLabel': dataset.label,
            'model': getattr(settings, 'OLLAMA_DEFAULT_MODEL', 'gemma4:cloud'),
            'historyLimit': getattr(settings, 'CHATBOT_HISTORY_LIMIT', 8),
            'maxQuestionLength': getattr(settings, 'CHATBOT_MAX_QUESTION_LENGTH', 2000),
        }

        snippet = render_to_string('chatbot/widget.html', {'config': config}, request=request)
        snippet_bytes = snippet.encode(response.charset or 'utf-8')

        lowered = content.lower()
        body_end = lowered.rfind(b'</body>')
        if body_end != -1:
            content = content[:body_end] + snippet_bytes + content[body_end:]
        else:
            content = content + snippet_bytes

        response.content = content
        if response.has_header('Content-Length'):
            response['Content-Length'] = str(len(content))
