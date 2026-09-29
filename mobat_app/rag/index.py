from __future__ import annotations

import logging
import re
import threading
from collections import OrderedDict

import numpy as np
from django.conf import settings
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer

from .corpus import Document

logger = logging.getLogger(__name__)

WORD_MAX_FEATURES = 100_000
CHAR_MAX_FEATURES = 40_000

TITLE_REPEAT = 3
IDENTIFIER_BONUS = 0.15

PORTUGUESE_STOPWORDS = frozenset({
    'a', 'o', 'os', 'as', 'um', 'uma', 'de', 'do', 'da', 'dos', 'das',
    'no', 'na', 'nos', 'nas', 'em', 'com', 'por', 'para', 'sem', 'sob',
    'sobre', 'que', 'qual', 'quais', 'quanto', 'quanta', 'como', 'quando',
    'onde', 'quem', 'se', 'ou', 'e', 'era', 'ao', 'aos',
    'pelo', 'pela', 'pelos', 'pelas', 'num', 'numa', 'entre',
    'apos', 'ate', 'ja', 'mas', 'muito', 'muitos', 'muitas', 'todo', 'toda',
    'todos', 'todas', 'este', 'esta', 'esse', 'essa', 'isso', 'isto',
    'aquilo', 'ela', 'ele', 'eles', 'elas', 'eu', 'voce', 'lhe', 'deles',
    'delas', 'the', 'and', 'of', 'in', 'for', 'to', 'is', 'at', 'on',
})

IDENTIFIER_RE = re.compile(r'[a-z][a-z0-9]*(?:_[a-z0-9]+)+')


class VectorIndex:

    def __init__(self, documents: list[Document]):
        if not documents:
            raise ValueError('Não é possível indexar uma lista vazia de documentos')

        self.documents = documents
        texts = [indexed_text(document) for document in documents]

        doc_count = len(texts)
        default_char_min_df = 3 if doc_count >= 50 else (2 if doc_count >= 20 else 1)
        word_min_df = int(getattr(settings, 'RAG_WORD_MIN_DF', 0)) or 1
        char_min_df = int(getattr(settings, 'RAG_CHAR_MIN_DF', 0)) or default_char_min_df

        self.word_vectorizer = TfidfVectorizer(
            analyzer='word',
            ngram_range=(1, 2),
            token_pattern=r'(?u)[\w./%_-]+',
            min_df=word_min_df,
            max_features=WORD_MAX_FEATURES,
            sublinear_tf=True,
            strip_accents='unicode',
            stop_words=sorted(PORTUGUESE_STOPWORDS),
        )
        self.char_vectorizer = TfidfVectorizer(
            analyzer='char_wb',
            ngram_range=(3, 5),
            min_df=char_min_df,
            max_features=CHAR_MAX_FEATURES,
            sublinear_tf=True,
        )

        word_matrix = self.word_vectorizer.fit_transform(texts)
        char_matrix = self.char_vectorizer.fit_transform(texts)
        self.matrix: csr_matrix = _normalize(hstack([word_matrix, char_matrix]).tocsr())

        self._identifiers: dict[str, list[int]] = {}
        for position, document in enumerate(documents):
            for identifier in set(IDENTIFIER_RE.findall(f'{document.id} {document.title}'.lower())):
                self._identifiers.setdefault(identifier, []).append(position)

    @property
    def size(self) -> int:
        return len(self.documents)

    def vectorize_query(self, query: str) -> csr_matrix:
        word = self.word_vectorizer.transform([query])
        char = self.char_vectorizer.transform([query])
        return _normalize(hstack([word, char]).tocsr())

    def search(
        self,
        query: str,
        k: int = 12,
        threshold: float = 0.0,
    ) -> list[tuple[Document, float]]:
        query = (query or '').strip()
        if not query:
            return []

        query_vector = self.vectorize_query(query)
        if query_vector.nnz == 0:
            return []

        scores = (self.matrix @ query_vector.T).toarray().ravel().astype(float)
        if IDENTIFIER_BONUS:
            lowered = query.lower()
            for identifier, positions in self._identifiers.items():
                if identifier in lowered:
                    for position in positions:
                        scores[position] = min(1.0, scores[position] + IDENTIFIER_BONUS)

        order = np.argsort(scores)[::-1]

        results: list[tuple[Document, float]] = []
        for index in order:
            score = float(scores[index])
            if score < threshold:
                break
            results.append((self.documents[int(index)], score))
            if len(results) >= max(1, k):
                break
        return results


def indexed_text(document: Document) -> str:
    return f'{document.title}. ' * TITLE_REPEAT + document.text


def _normalize(matrix) -> csr_matrix:
    from sklearn.preprocessing import normalize as _sk_normalize

    return _sk_normalize(matrix, norm='l2', axis=1, copy=True).tocsr()


_CACHE_MAX_ENTRIES = 2

_cache: OrderedDict[str, tuple[object, VectorIndex]] = OrderedDict()
_cache_lock = threading.Lock()
_build_locks: dict[str, threading.Lock] = {}


def get_index(dataset, documents_loader=None, force: bool = False) -> VectorIndex:
    from .datasets import dataframe_fingerprint
    from .corpus import build_documents
    from .datasets import load_dataframe

    fingerprint = dataframe_fingerprint(dataset)
    with _cache_lock:
        cached = _cache.get(dataset.key)
        if cached is not None and cached[0] == fingerprint and not force:
            _cache.move_to_end(dataset.key)
            return cached[1]

    build_lock = _build_locks.setdefault(dataset.key, threading.Lock())
    with build_lock:
        with _cache_lock:
            cached = _cache.get(dataset.key)
            if cached is not None and cached[0] == fingerprint and not force:
                _cache.move_to_end(dataset.key)
                return cached[1]

        import time

        started = time.monotonic()
        if documents_loader is not None:
            documents = documents_loader()
        else:
            dataframe = load_dataframe(dataset)
            documents = build_documents(dataframe, dataset)

        index = VectorIndex(documents)
        logger.info(
            'Índice do dataset %s construído em %.2fs (%d documentos)',
            dataset.key,
            time.monotonic() - started,
            index.size,
        )

        with _cache_lock:
            _cache[dataset.key] = (fingerprint, index)
            _cache.move_to_end(dataset.key)
            while len(_cache) > _CACHE_MAX_ENTRIES:
                _cache.popitem(last=False)
        return index


def warmup(dataset, force: bool = False) -> threading.Thread | None:
    with _cache_lock:
        cached = _cache.get(dataset.key)
        if cached is not None and not force:
            return None
        if any(thread.name == f'rag-warmup-{dataset.key}' for thread in threading.enumerate()):
            return None

    def _worker() -> None:
        try:
            get_index(dataset, force=force)
        except Exception:  # noqa: BLE001
            logger.exception('Falha ao pré-queimar o índice do dataset %s', dataset.key)

    thread = threading.Thread(target=_worker, name=f'rag-warmup-{dataset.key}', daemon=True)
    thread.start()
    return thread


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def index_status(dataset) -> dict:
    from .datasets import dataframe_fingerprint

    with _cache_lock:
        cached = _cache.get(dataset.key)
        if cached is None:
            return {'ready': False, 'documents': 0, 'stale': False}
        return {
            'ready': True,
            'documents': cached[1].size,
            'stale': cached[0] != dataframe_fingerprint(dataset),
        }
