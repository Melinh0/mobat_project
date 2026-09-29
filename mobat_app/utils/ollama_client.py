from __future__ import annotations

import json
import threading
import time
from typing import Any

import requests
from django.conf import settings


class OllamaError(Exception):

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class OllamaRateLimited(OllamaError):
    pass


class _RateLimiter:

    def __init__(self, min_interval: float):
        self._min_interval = max(0.0, min_interval)
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        if self._min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            start_at = max(now, self._next_allowed)
            self._next_allowed = start_at + self._min_interval
            delay = start_at - now
        if delay > 0:
            time.sleep(delay)


class OllamaClient:

    def __init__(
        self,
        host: str | None = None,
        api_keys: list[str] | None = None,
        default_model: str | None = None,
    ):
        self.host = (host or getattr(settings, 'OLLAMA_HOST', 'https://ollama.com')).rstrip('/')
        self.api_keys = list(api_keys if api_keys is not None else getattr(settings, 'OLLAMA_API_KEYS', []))
        self.default_model = default_model or getattr(settings, 'OLLAMA_DEFAULT_MODEL', 'gemma4:cloud')

        self.max_tokens = getattr(settings, 'OLLAMA_MAX_TOKENS', 16000)
        self.request_timeout = getattr(settings, 'OLLAMA_REQUEST_TIMEOUT', 600)
        self.connect_timeout = getattr(settings, 'OLLAMA_CONNECT_TIMEOUT', 15)
        self.max_retries = max(0, getattr(settings, 'OLLAMA_MAX_RETRIES', 3))
        self.backoff_base = getattr(settings, 'OLLAMA_RATE_LIMIT_BACKOFF_BASE', 5)
        self.backoff_max = getattr(settings, 'OLLAMA_RATE_LIMIT_MAX_BACKOFF', 120)

        concurrency = max(1, getattr(settings, 'OLLAMA_MAX_CONCURRENT_REQUESTS', 4))
        self._semaphore = threading.BoundedSemaphore(concurrency)
        self._rate_limiter = _RateLimiter(getattr(settings, 'OLLAMA_MIN_REQUEST_INTERVAL', 0.5))

        self._key_lock = threading.Lock()
        self._key_index = 0

        self.session = requests.Session()

    def _next_key(self) -> str | None:
        with self._key_lock:
            if not self.api_keys:
                return None
            key = self.api_keys[self._key_index % len(self.api_keys)]
            self._key_index += 1
            return key

    def _reset_keys(self) -> None:
        with self._key_lock:
            self._key_index = 0

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.host}{path}"
        attempts = self.max_retries + 1
        last_error: Exception | None = None
        status_code: int | None = None

        for attempt in range(attempts):
            key = self._next_key()
            headers = {'Content-Type': 'application/json'}
            if key:
                headers['Authorization'] = f'Bearer {key}'

            self._rate_limiter.wait()
            try:
                with self._semaphore:
                    response = self.session.post(
                        url,
                        headers=headers,
                        data=json.dumps(payload),
                        timeout=(self.connect_timeout, self.request_timeout),
                    )
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = OllamaError(f"Falha de conexão com o Ollama: {exc}")
                status_code = None
                self._sleep_backoff(attempt)
                continue

            status_code = response.status_code

            if response.status_code == 200:
                try:
                    return response.json()
                except ValueError as exc:
                    last_error = OllamaError(f"Resposta inválida do Ollama: {exc}", 200)
                    self._sleep_backoff(attempt)
                    continue

            if response.status_code in (401, 403):
                last_error = OllamaError(
                    f"Chave recusada pelo Ollama (HTTP {response.status_code}): "
                    f"{response.text[:200]}",
                    response.status_code,
                )
                continue

            if response.status_code == 429:
                last_error = OllamaRateLimited(
                    f"Rate limit do Ollama (HTTP 429): {response.text[:200]}", 429
                )
                retry_after = self._retry_after(response)
                self._sleep_backoff(attempt, override=retry_after)
                continue

            if response.status_code >= 500:
                last_error = OllamaError(
                    f"Erro interno do Ollama (HTTP {response.status_code}): {response.text[:200]}",
                    response.status_code,
                )
                self._sleep_backoff(attempt)
                continue

            raise OllamaError(
                f"Ollama recusou a requisição (HTTP {response.status_code}): {response.text[:300]}",
                response.status_code,
            )

        self._reset_keys()
        if last_error is None:
            last_error = OllamaError("Falha desconhecida ao chamar o Ollama", status_code)
        if isinstance(last_error, OllamaRateLimited) and attempt >= attempts - 1:
            raise OllamaRateLimited(
                f"Chaves esgotadas por rate limit após {attempts} tentativas", 429
            )
        raise last_error

    @staticmethod
    def _retry_after(response: requests.Response) -> float | None:
        raw = response.headers.get('Retry-After')
        if not raw:
            return None
        try:
            return max(0.0, float(raw))
        except ValueError:
            return None

    def _sleep_backoff(self, attempt: int, override: float | None = None) -> None:
        if override is not None:
            delay = min(override, self.backoff_max)
        else:
            delay = min(self.backoff_base * (2 ** attempt), self.backoff_max)
        if delay > 0:
            time.sleep(delay)

    def chat(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
        json_format: bool = False,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not messages:
            raise OllamaError("Nenhuma mensagem enviada ao modelo")

        payload_options: dict[str, Any] = {
            'temperature': temperature,
            'num_predict': max_tokens or self.max_tokens,
        }
        if options:
            payload_options.update(options)

        payload: dict[str, Any] = {
            'model': model or self.default_model,
            'messages': messages,
            'stream': False,
            'options': payload_options,
        }
        if json_format:
            payload['format'] = 'json'

        return self._post('/api/chat', payload)

    def chat_text(self, messages: list[dict[str, str]], **kwargs) -> str:
        data = self.chat(messages, **kwargs)
        content = (data.get('message') or {}).get('content', '')
        if not content:
            raise OllamaError(f"Resposta vazia do modelo ({data.get('done_reason', 'sem motivo')})")
        return content


_client: OllamaClient | None = None
_client_lock = threading.Lock()


def get_client() -> OllamaClient:
    global _client
    if _client is None:
        with _client_lock:
            if _client is None:
                _client = OllamaClient()
    return _client


def reset_client() -> None:
    global _client
    with _client_lock:
        _client = None


def chat(messages: list[dict[str, str]], **kwargs) -> dict[str, Any]:
    return get_client().chat(messages, **kwargs)


def chat_text(messages: list[dict[str, str]], **kwargs) -> str:
    return get_client().chat_text(messages, **kwargs)
