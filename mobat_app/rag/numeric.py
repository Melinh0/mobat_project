from __future__ import annotations

import re

import pandas as pd

PLAUSIBLE_MIN = 1.0
PLAUSIBLE_MAX = 500.0
MIN_VALID_FOR_REFERENCE = 10

_MANGLED_PATTERN = re.compile(r'^\d{1,3}(?:\.\d{3})+$')
_TRUE = {'true', '1', 'sim', 'yes'}


def to_numeric_clean(series: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(series):
        return series.astype(float)

    if pd.api.types.is_numeric_dtype(series):
        return pd.to_numeric(series, errors='coerce').astype(float)

    text = series.astype(str).str.strip()
    text = text.mask(text.isin(['', 'nan', 'None', 'NaN', '<NA>']), None)
    filled = text.fillna('')

    direct = pd.to_numeric(filled.str.replace(',', '.', regex=False), errors='coerce')

    mangled = filled.ne('') & filled.str.match(_MANGLED_PATTERN) & direct.isna()
    if not mangled.any():
        return direct.astype(float)

    valid = direct.dropna()
    center = float(valid.median()) if len(valid) >= MIN_VALID_FOR_REFERENCE else 50.0

    repaired = direct.astype(float)
    labels = filled[mangled].unique()
    mapping = {label: _reconstruct(label, center) for label in labels}
    repaired.loc[mangled] = filled[mangled].map(mapping)

    return repaired


def _reconstruct(label: str, center: float) -> float:
    digits = label.replace('.', '')
    if not digits.isdigit():
        return float('nan')
    try:
        base = float(digits)
    except ValueError:
        return float('nan')

    best = float('nan')
    best_distance: float | None = None
    divisor = 1.0
    for position in range(len(digits)):
        if position:
            divisor *= 10.0
        candidate = base / divisor
        if PLAUSIBLE_MIN <= candidate <= PLAUSIBLE_MAX:
            distance = abs(candidate - center)
            if best_distance is None or distance < best_distance:
                best, best_distance = candidate, distance
    return best


def looks_numeric(series: pd.Series) -> bool:
    if pd.api.types.is_numeric_dtype(series):
        return True
    if pd.api.types.is_bool_dtype(series):
        return True
    cleaned = to_numeric_clean(series)
    return bool(cleaned.notna().mean() >= 0.5)


def describe_clean(series: pd.Series) -> tuple[pd.Series, int]:
    cleaned = to_numeric_clean(series)
    if pd.api.types.is_numeric_dtype(series):
        return cleaned, 0
    direct = pd.to_numeric(series, errors='coerce')
    repaired = int((cleaned.notna() & direct.isna()).sum())
    return cleaned, repaired


def to_bool(series: pd.Series) -> pd.Series:
    if pd.api.types.is_bool_dtype(series):
        return series.astype(bool)
    text = series.astype(str).str.strip().str.lower()
    parsed = text.isin(_TRUE)
    numeric = pd.to_numeric(series, errors='coerce')
    parsed = parsed | (numeric.fillna(0) > 0)
    return parsed
