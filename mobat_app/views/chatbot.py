from __future__ import annotations

import json
import logging

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST

from ..rag import service
from ..rag.datasets import DATASETS, dataset_from_session
from ..utils.ollama_client import OllamaError

logger = logging.getLogger(__name__)


def _parse_payload(request) -> dict:
    if request.content_type and 'application/json' in request.content_type:
        try:
            payload = json.loads(request.body.decode('utf-8') or '{}')
        except (ValueError, UnicodeDecodeError):
            return {}
        return payload if isinstance(payload, dict) else {}

    return {key: value for key, value in request.POST.items()}


def _error(message: str, status: int = 400) -> JsonResponse:
    return JsonResponse({'error': message}, status=status)


@require_GET
def chatbot_status(request):
    dataset = dataset_from_session(request.session)
    if not settings.CHATBOT_ENABLED:
        return JsonResponse({'enabled': False, 'dataset': dataset.label})

    status = service.dataset_status(dataset)
    status['enabled'] = True

    if not status['index_ready']:
        from ..rag.index import warmup

        warmup(dataset)

    return JsonResponse(status)


@require_POST
def chatbot_ask(request):
    if not settings.CHATBOT_ENABLED:
        return _error('Chatbot desativado nas configurações', 403)

    payload = _parse_payload(request)
    question = str(payload.get('question') or '').strip()
    if not question:
        return _error('Informe uma pergunta')
    if len(question) > getattr(settings, 'CHATBOT_MAX_QUESTION_LENGTH', 2000):
        return _error(
            f'Pergunta longa demais (máximo {getattr(settings, "CHATBOT_MAX_QUESTION_LENGTH", 2000)} caracteres)'
        )

    dataset_key = str(payload.get('dataset_key') or '').strip()
    if dataset_key and dataset_key in DATASETS:
        dataset = DATASETS[dataset_key]
    else:
        dataset = dataset_from_session(request.session)

    history = payload.get('history') or []
    if not isinstance(history, list):
        history = []
    history = [item for item in history if isinstance(item, dict)][-20:]

    try:
        answer = service.ask(question, dataset, history=history)
    except OllamaError as exc:
        logger.warning('Falha do Ollama em /chatbot/ask/: %s', exc)
        return _error(f'Não consegui consultar o modelo de IA: {exc}', 502)
    except FileNotFoundError as exc:
        return _error(str(exc), 404)
    except Exception as exc:  # noqa: BLE001
        logger.exception('Erro inesperado no chatbot')
        return _error(f'Erro interno ao gerar a resposta: {exc}', 500)

    return JsonResponse(answer.as_dict())
