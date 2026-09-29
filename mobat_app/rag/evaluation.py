from __future__ import annotations

import math

import numpy as np
from scipy.stats import mannwhitneyu

POSITIVE_BATTERY: list[dict] = [
    {'query': 'qual país tem mais IPs', 'expect': [':agg:abuseipdb_country_code']},
    {'query': 'qual o isp com mais endereços IP', 'expect': [':agg:abuseipdb_isp']},
    {'query': 'quais são os IPs com pior reputação', 'expect': [':agg:worst_ips']},
    {'query': 'quais IPs foram mais denunciados', 'expect': [':agg:most_reported']},
    {'query': 'como são as faixas de score dos IPs', 'expect': [':agg:score_bands']},
    {'query': 'quantos IPs existem na base', 'expect': [':overview']},
    {'query': 'quantas denúncias o AbuseIPDB registra', 'expect': [':column:abuseipdb_total_reports', ':agg:most_reported']},
    {'query': 'o que significa a coluna abuseipdb_country_code', 'expect': [':column:abuseipdb_country_code']},
    {'query': 'qual a média do score_average_Mobat', 'expect': [':column:score_average_Mobat', ':agg:score_bands']},
    {'query': 'quais colunas medem denúncias do AbuseIPDB', 'expect': [':column:abuseipdb_total_reports', ':column:abuseipdb_num_distinct_users']},
    {'query': 'como o Brasil se compara aos demais países', 'expect': [':agg:abuseipdb_country_code']},
]

NOISE_BATTERY: list[str] = [
    'como fazer bolo de cenoura',
    'qual a previsão do tempo em Tóquio para amanhã',
    'receita de bolo de formiga com leite condensado',
    'quem venceu a copa do mundo de futebol de 1994',
    'dicas de jardinagem para orquídeas em apartamento',
    'melhor smartphone custo-benefício de 2026',
    'como funciona async await em python',
    'receita de pão de queijo mineiro',
    'qual o melhor time de futebol do mundo',
    'história da aviação dos primeiros aviões',
]


def _score_stats(values: np.ndarray) -> dict:
    if values.size == 0:
        return {'n': 0}
    return {
        'n': int(values.size),
        'mean': float(np.mean(values)),
        'std': float(np.std(values, ddof=1)) if values.size > 1 else 0.0,
        'median': float(np.median(values)),
        'p10': float(np.percentile(values, 10)),
        'p90': float(np.percentile(values, 90)),
        'min': float(np.min(values)),
        'max': float(np.max(values)),
    }


def _auc(positive: np.ndarray, negative: np.ndarray) -> float:
    if positive.size == 0 or negative.size == 0:
        return float('nan')
    wins = 0.0
    for value in positive:
        wins += float(np.sum(value > negative)) + 0.5 * float(np.sum(value == negative))
    return wins / float(positive.size * negative.size)


def _youden_threshold(positive: np.ndarray, negative: np.ndarray) -> float:
    if positive.size == 0 or negative.size == 0:
        return float('nan')
    candidates = np.unique(np.concatenate([positive, negative]))
    best_threshold, best_j = float('nan'), -1.0
    for threshold in candidates:
        true_positive_rate = float(np.mean(positive >= threshold))
        false_positive_rate = float(np.mean(negative >= threshold))
        j = true_positive_rate - false_positive_rate
        if j > best_j:
            best_threshold, best_j = float(threshold), j
    return best_threshold


def _service_results(index, query: str, k: int, threshold: float) -> list:
    results = index.search(query, k=k, threshold=threshold)
    if not results:
        results = index.search(query, k=k, threshold=min(threshold, 0.1))
    if not results:
        results = index.search(query, k=min(k, 5), threshold=0.0)
    return results


def evaluate_index(index, battery=None, noise=None, k: int = 5, threshold: float = 0.15) -> dict:
    from django.conf import settings

    battery = POSITIVE_BATTERY if battery is None else battery
    noise = NOISE_BATTERY if noise is None else noise
    production_k = int(getattr(settings, 'RAG_N_RESULTS', 12))
    depth = max(k, production_k)

    positives = []
    for item in battery:
        results = index.search(item['query'], k=depth, threshold=0.0)
        hits = [
            position
            for position, (document, _score) in enumerate(results, start=1)
            if any(expected in document.id for expected in item['expect'])
        ]
        first_hit = hits[0] if hits else None
        top_score = float(results[0][1]) if results else 0.0
        final_ids = [document.id for document, _score in _service_results(index, item['query'], production_k, threshold)]
        positives.append({
            'query': item['query'],
            'expect': item['expect'],
            'top_score': top_score,
            'hit': first_hit is not None and first_hit <= k,
            'hit_at_production_k': first_hit is not None and first_hit <= production_k,
            'hit_in_service_flow': any(
                expected in document_id for document_id in final_ids for expected in item['expect']
            ),
            'rank': first_hit,
            'reciprocal_rank': (1.0 / first_hit) if first_hit and first_hit <= k else 0.0,
            'reciprocal_rank_at_production_k': (
                1.0 / first_hit if first_hit and first_hit <= production_k else 0.0
            ),
            'precision_at_k': (
                sum(1 for position in hits if position <= k) / k
            ),
            'results': [
                {'id': document.id, 'title': document.title, 'score': round(score, 4)}
                for document, score in results
            ],
        })

    negatives = []
    for query in noise:
        results = index.search(query, k=depth, threshold=0.0)
        top_score = float(results[0][1]) if results else 0.0
        negatives.append({
            'query': query,
            'top_score': top_score,
            'above_threshold': top_score >= threshold,
        })

    positive_scores = np.array([item['top_score'] for item in positives], dtype=float)
    negative_scores = np.array([item['top_score'] for item in negatives], dtype=float)

    auc = _auc(positive_scores, negative_scores)
    if positive_scores.size and negative_scores.size:
        statistic, p_value = mannwhitneyu(positive_scores, negative_scores, alternative='greater')
        statistic, p_value = float(statistic), float(p_value)
    else:
        statistic, p_value = float('nan'), float('nan')

    hits = [item for item in positives if item['hit']]
    metrics = {
        'hit_rate_at_k': len(hits) / len(positives) if positives else 0.0,
        'hit_rate_at_production_k': (
            float(np.mean([item['hit_at_production_k'] for item in positives])) if positives else 0.0
        ),
        'mean_reciprocal_rank': float(np.mean([item['reciprocal_rank'] for item in positives])) if positives else 0.0,
        'mean_reciprocal_rank_at_production_k': (
            float(np.mean([item['reciprocal_rank_at_production_k'] for item in positives])) if positives else 0.0
        ),
        'precision_at_k': float(np.mean([item['precision_at_k'] for item in positives])) if positives else 0.0,
        'recall_at_threshold': float(np.mean([item['top_score'] >= threshold for item in positives])) if positives else 0.0,
        'recall_with_fallback': (
            float(np.mean([item['hit_in_service_flow'] for item in positives])) if positives else 0.0
        ),
        'false_positive_rate_at_threshold': (
            float(np.mean([item['above_threshold'] for item in negatives])) if negatives else 0.0
        ),
        'auc': auc,
        'mann_whitney_u': statistic,
        'p_value': p_value,
        'separable': bool(
            positive_scores.size
            and negative_scores.size
            and float(np.min(positive_scores)) > float(np.max(negative_scores))
        ),
        'recommended_threshold': _youden_threshold(positive_scores, negative_scores),
        'positive_scores': _score_stats(positive_scores),
        'negative_scores': _score_stats(negative_scores),
    }
    metrics['verdict'] = _verdict(metrics)

    return {
        'documents': index.size,
        'k': k,
        'production_k': production_k,
        'threshold': threshold,
        'positives': positives,
        'negatives': negatives,
        'metrics': metrics,
    }


def _verdict(metrics: dict) -> str:
    auc = metrics['auc']
    if math.isnan(auc):
        return 'INCONCLUSIVO'
    if auc >= 0.9 and metrics['hit_rate_at_k'] >= 0.75 and metrics['false_positive_rate_at_threshold'] <= 0.25:
        return 'BOM'
    if auc >= 0.75 and metrics['hit_rate_at_k'] >= 0.5:
        return 'REGULAR'
    return 'RUIM'


def format_report(report: dict) -> str:
    metrics = report['metrics']
    positive = metrics['positive_scores']
    negative = metrics['negative_scores']
    threshold = report['threshold']
    k = report['k']

    lines = [
        f'Avaliação do índice ({report["documents"]} documentos, k={k}, limiar={threshold:.2f})',
        '',
        'Perguntas positivas (espera-se o documento indicado):',
    ]
    for item in report['positives']:
        if item['rank']:
            status = f'r={item["rank"]}' + ('!' if item['rank'] > k else '')
        else:
            status = 'MISS'
        lines.append(f'  [{status:>6}] top1={item["top_score"]:.3f}  {item["query"]}')
    lines.append(f'  (r = posição do documento esperado; "!" = fora de top-{k} mas dentro da produção)')

    lines.append('')
    lines.append('Perguntas de ruído (grupo de controle):')
    for item in report['negatives']:
        flag = 'acima do limiar' if item['above_threshold'] else 'abaixo do limiar'
        lines.append(f'  top1={item["top_score"]:.3f} ({flag})  {item["query"]}')

    production_k = report.get('production_k', 12)
    lines.extend([
        '',
        'Métricas de recuperação:',
        f'  hit@{k} (acerto do documento esperado):  {metrics["hit_rate_at_k"]:.2f}',
        f'  hit@{production_k} (profundidade real):     {metrics["hit_rate_at_production_k"]:.2f}',
        f'  precision@{k} média:                    {metrics["precision_at_k"]:.3f}',
        f'  MRR@{k}:                                     {metrics["mean_reciprocal_rank"]:.3f}',
        f'  MRR@{production_k}:                                    {metrics["mean_reciprocal_rank_at_production_k"]:.3f}',
        f'  recall no limiar {threshold:.2f}:                {metrics["recall_at_threshold"]:.2f}',
        f'  recall no fluxo do serviço:             {metrics["recall_with_fallback"]:.2f}',
        f'  falsos positivos no limiar:              {metrics["false_positive_rate_at_threshold"]:.2f}',
        '',
        'Separação sinal × ruído (similaridade do 1º resultado):',
        f'  positivas: média={positive.get("mean", 0):.3f}, desvio={positive.get("std", 0):.3f}, '
        f'mediana={positive.get("median", 0):.3f}, P10={positive.get("p10", 0):.3f}, P90={positive.get("p90", 0):.3f}',
        f'  ruído:     média={negative.get("mean", 0):.3f}, desvio={negative.get("std", 0):.3f}, '
        f'mediana={negative.get("median", 0):.3f}, P10={negative.get("p10", 0):.3f}, P90={negative.get("p90", 0):.3f}',
        f'  AUC: {metrics["auc"]:.3f}  |  Mann-Whitney U={metrics["mann_whitney_u"]:.0f}, p={metrics["p_value"]:.2e}',
        f'  grupos separáveis por limiar: {"sim" if metrics["separable"] else "não"}',
        f'  limiar sugerido (Youden): {metrics["recommended_threshold"]:.3f}',
        '',
        f'VERDICTO: {metrics["verdict"]}',
    ])
    return '\n'.join(lines)
