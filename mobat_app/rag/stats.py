from __future__ import annotations

import math

import numpy as np
import pandas as pd

from .numeric import to_numeric_clean

TARGET_COLUMN = 'score_average_Mobat'

DESCRIPTIVE_COLUMNS = [
    'score_average_Mobat',
    'abuseipdb_confidence_score',
    'abuseipdb_total_reports',
    'abuseipdb_num_distinct_users',
    'virustotal_reputation',
    'harmless',
    'malicious',
    'suspicious',
    'undetected',
    'IBM_score',
    'IBM_average history Score',
]

MAX_DESCRIPTIVE_COLUMNS = 8
TOP_CORRELATIONS = 6

_cache: dict[tuple[int, int], str] = {}


def _fmt(value: float) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return 'sem dado'
    if float(value).is_integer() and abs(value) < 1e15:
        return str(int(value))
    return f'{float(value):.3g}'


def _clean(df: pd.DataFrame, column: str) -> pd.Series | None:
    if column not in df.columns:
        return None
    series = to_numeric_clean(df[column]).dropna()
    if series.empty or series.nunique() < 2:
        return None
    return series.astype(float)


def describe_series(series: pd.Series) -> dict[str, float]:
    quantiles = series.quantile([0.25, 0.5, 0.75, 0.9])
    iqr = float(quantiles.loc[0.75] - quantiles.loc[0.25])
    lower = float(quantiles.loc[0.25]) - 1.5 * iqr
    upper = float(quantiles.loc[0.75]) + 1.5 * iqr
    outliers = int(((series < lower) | (series > upper)).sum())
    mean = float(series.mean())
    std = float(series.std(ddof=1)) if len(series) > 1 else 0.0

    return {
        'n': int(series.count()),
        'média': mean,
        'desvio': std,
        'cv': std / mean if mean else float('nan'),
        'min': float(series.min()),
        'P25': float(quantiles.loc[0.25]),
        'mediana': float(quantiles.loc[0.5]),
        'P75': float(quantiles.loc[0.75]),
        'P90': float(quantiles.loc[0.9]),
        'máx': float(series.max()),
        'assimetria': float(series.skew()) if len(series) > 2 else 0.0,
        'outliers': outliers,
        'outliers_pct': 100 * outliers / len(series),
    }


def descriptive_block(df: pd.DataFrame) -> str:
    lines = []
    used = 0
    for column in DESCRIPTIVE_COLUMNS:
        if used >= MAX_DESCRIPTIVE_COLUMNS:
            break
        series = _clean(df, column)
        if series is None:
            continue
        stats = describe_series(series)
        lines.append(
            f'- {column}: n={stats["n"]}, média={_fmt(stats["média"])}, desvio={_fmt(stats["desvio"])}, '
            f'CV={_fmt(stats["cv"])}, min={_fmt(stats["min"])}, P25={_fmt(stats["P25"])}, '
            f'mediana={_fmt(stats["mediana"])}, P75={_fmt(stats["P75"])}, P90={_fmt(stats["P90"])}, '
            f'máx={_fmt(stats["máx"])}, assimetria={_fmt(stats["assimetria"])}, '
            f'outliers IQR={stats["outliers"]} ({_fmt(stats["outliers_pct"])}%)'
        )
        used += 1

    if not lines:
        return ''
    return 'Medidas descritivas (pandas):\n' + '\n'.join(lines)


def _strength_label(value: float) -> str:
    magnitude = abs(value)
    if magnitude < 0.1:
        return 'desprezível'
    if magnitude < 0.3:
        return 'fraca'
    if magnitude < 0.5:
        return 'moderada'
    if magnitude < 0.7:
        return 'forte'
    return 'muito forte'


def correlation_block(df: pd.DataFrame, target: str = TARGET_COLUMN) -> str:
    target_series = _clean(df, target)
    if target_series is None:
        return ''

    columns = []
    for column in df.columns:
        if column == target:
            continue
        series = _clean(df, column)
        if series is not None:
            columns.append(column)
    if not columns:
        return ''

    numeric = pd.DataFrame({column: to_numeric_clean(df[column]) for column in columns})
    numeric[target] = target_series
    numeric = numeric.dropna()

    if len(numeric) < 10:
        return ''

    pearson = numeric.corr(method='pearson')[target].drop(labels=[target], errors='ignore')
    spearman = numeric.corr(method='spearman')[target].drop(labels=[target], errors='ignore')

    ranking = spearman.reindex(spearman.abs().sort_values(ascending=False).index).dropna()
    ranking = ranking[ranking.abs() > 0.05].head(TOP_CORRELATIONS)
    if ranking.empty:
        return f'Correlação de {target} com as demais variáveis: nenhuma relação perceptível (|ρ| < 0.05).'

    lines = [f'Correlação com {target} (Spearman ρ / Pearson r):']
    for column, rho in ranking.items():
        r = float(pearson.get(column, float('nan')))
        lines.append(
            f'- {column}: ρ={_fmt(float(rho))}, r={_fmt(r)} '
            f'({_strength_label(float(rho))} {"positiva" if float(rho) > 0 else "negativa"})'
        )
    lines.append('Correlação não implica causalidade; use-a apenas como associação.')
    return '\n'.join(lines)


def statistical_summary(df: pd.DataFrame, use_cache: bool = True) -> str:
    key = (id(df), len(df))
    if use_cache and key in _cache:
        return _cache[key]

    parts = [
        'RESUMO ESTATÍSTICO (calculado com pandas/numpy sobre a base inteira)',
        descriptive_block(df),
        correlation_block(df),
    ]
    block = '\n\n'.join(part for part in parts if part)
    block += (
        '\n\nUse estes números como autoridade ao comparar valores, citar dispersão '
        '(desvio/quartis) ou falar em associação entre variáveis.'
    )

    if use_cache:
        if len(_cache) > 8:
            _cache.clear()
        _cache[key] = block
    return block


def clear_cache() -> None:
    _cache.clear()
