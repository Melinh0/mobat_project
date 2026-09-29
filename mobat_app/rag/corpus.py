from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
import pandas as pd
from django.conf import settings

from .datasets import COLUMN_HELP, Dataset, country_label
from .numeric import describe_clean, to_numeric_clean

OVERVIEW = 'overview'
COLUMN = 'column'
AGGREGATE = 'aggregate'
ROWS = 'rows'

KIND_LABELS = {
    OVERVIEW: 'Visão geral do período',
    COLUMN: 'Perfil de coluna',
    AGGREGATE: 'Agregação estatística',
    ROWS: 'Linhas da tabela',
}

DEFAULT_MIN_ROWS_PER_CHUNK = 10


@dataclass(frozen=True)
class Document:
    id: str
    kind: str
    title: str
    text: str

    @property
    def kind_label(self) -> str:
        return KIND_LABELS.get(self.kind, self.kind)

    def as_context(self) -> str:
        return f"[{self.kind_label} | {self.title}]\n{self.text}"


def min_rows_per_chunk() -> int:
    return max(1, int(getattr(settings, 'INDEX_MIN_ROWS_PER_CHUNK', DEFAULT_MIN_ROWS_PER_CHUNK)))


def chunk_target_size() -> int:
    return max(50, int(getattr(settings, 'INDEX_CHUNK_TARGET_SIZE', 500)))


def chunk_overlap() -> int:
    return max(0, int(getattr(settings, 'INDEX_CHUNK_OVERLAP', 80)))


def _fmt_number(value) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return 'sem dado'
    if isinstance(value, (bool, np.bool_)):
        return 'true' if bool(value) else 'false'
    if isinstance(value, (int, np.integer)):
        return str(int(value))
    if isinstance(value, (float, np.floating)):
        number = float(value)
        if number.is_integer() and abs(number) < 1e15:
            return str(int(number))
        return f'{number:.4g}'
    return str(value)


def _is_numeric(series: pd.Series) -> bool:
    return pd.api.types.is_numeric_dtype(series) and not pd.api.types.is_bool_dtype(series)


def _top_values(series: pd.Series, limit: int = 10) -> list[tuple[str, int]]:
    cleaned = series.dropna().astype(str).str.strip()
    cleaned = cleaned[cleaned != '']
    if cleaned.empty:
        return []
    counts = cleaned.value_counts().head(limit)
    return [(str(value), int(count)) for value, count in counts.items()]


def _describe_numeric(series: pd.Series) -> str:
    clean = to_numeric_clean(series).dropna()
    if clean.empty:
        return 'sem valores numéricos'
    stats = {
        'média': clean.mean(),
        'mediana': clean.median(),
        'mín': clean.min(),
        'máx': clean.max(),
        'desvio padrão': clean.std() if len(clean) > 1 else 0.0,
        'P90': clean.quantile(0.9),
        'preenchidos': int(clean.count()),
    }
    return ', '.join(f'{name}={_fmt_number(value)}' for name, value in stats.items())


def build_documents(df: pd.DataFrame, dataset: Dataset) -> list[Document]:
    documents: list[Document] = [overview_document(df, dataset)]
    documents.extend(column_documents(df, dataset))
    documents.extend(aggregate_documents(df, dataset))
    documents.extend(row_documents(df, dataset))
    return documents


def overview_document(df: pd.DataFrame, dataset: Dataset) -> Document:
    total = len(df)
    lines = [
        f"Período: {dataset.label} | tabela: {dataset.table} | linhas: {total} | colunas: {len(df.columns)}.",
        f"Quantos IPs existem na base: {total} registros, um por endereço IP coletado "
        f"(total de linhas da tabela {dataset.table}).",
        "Cada linha representa um endereço IP coletado e avaliado por múltiplas fontes "
        "(AbuseIPDB, VirusTotal, IBM X-Force, Shodan, AlienVault).",
        "Métrica principal: score_average_Mobat = média dos scores das fontes (quanto maior, pior a reputação).",
        '',
        'Colunas disponíveis:',
    ]
    for column in df.columns:
        help_text = COLUMN_HELP.get(column, '')
        lines.append(f'- {column}' + (f': {help_text}' if help_text else ''))

    country_counts = _top_values(df['abuseipdb_country_code'], 8) if 'abuseipdb_country_code' in df else []
    if country_counts:
        lines.append('')
        lines.append(
            'Países com mais IPs: '
            + ', '.join(f'{country_label(code)} ({count})' for code, count in country_counts)
        )

    if 'score_average_Mobat' in df:
        numeric, repaired = describe_clean(df['score_average_Mobat'])
        numeric = numeric.dropna()
        if not numeric.empty:
            lines.append(
                f"score_average_Mobat: média={_fmt_number(numeric.mean())}, "
                f"mín={_fmt_number(numeric.min())}, máx={_fmt_number(numeric.max())} "
                f"sobre {int(numeric.count())} IPs."
            )
        if repaired:
            lines.append(
                f'Atenção: {repaired} de {total} valores de score_average_Mobat estavam gravados '
                'como texto com separador de milhar sobre o decimal (ex.: 4.642.857.142.857.140) '
                'e foram reparados para a mesma faixa dos valores legíveis. Use os agregados do '
                'contexto ou a função clean_number() antes de calcular com essa coluna.'
            )

    if 'malicious' in df:
        malicious = to_numeric_clean(df['malicious']).dropna()
        if not malicious.empty:
            lines.append(
                f'malicious (VirusTotal, escala 0-100): média={_fmt_number(malicious.mean())}, '
                f'mín={_fmt_number(malicious.min())}, máx={_fmt_number(malicious.max())}; '
                f'IPs com malicious >= 90: {int((malicious >= 90).sum())} de {total}.'
            )

    text = '\n'.join(lines)
    return Document(
        id=f'{dataset.key}:overview',
        kind=OVERVIEW,
        title=f'{dataset.label} – visão geral',
        text=text,
    )


def column_documents(df: pd.DataFrame, dataset: Dataset) -> list[Document]:
    documents: list[Document] = []
    total = len(df)
    for column in df.columns:
        series = df[column]
        help_text = COLUMN_HELP.get(column, '')
        filled = int(series.notna().sum())
        lines = [
            f'Coluna: {column}' + (f' – {help_text}' if help_text else ''),
            f'Tipo: {series.dtype} | preenchidos: {filled}/{total} ({_fmt_number(100 * filled / total if total else 0)}%).',
        ]
        if column == 'abuseipdb_country_code':
            lines.append(f'Significado: {COLUMN_HELP.get("abuseipdb_country_code", "")}.')

        repaired = 0
        if _is_numeric(series):
            lines.append('Estatísticas: ' + _describe_numeric(series) + '.')
        else:
            cleaned, repaired = describe_clean(series)
            if repaired:
                lines.append('Estatísticas (valores reparados): ' + _describe_numeric(cleaned) + '.')
                lines.append(
                    f'{repaired} de {total} valores estavam como texto com separador de milhar '
                    '(ex.: 4.642.857.142.857.140) e foram reconstruídos na faixa dos demais.'
                )
                lines.append('Use clean_number() no sandbox para converter essa coluna em cálculos.')

        top = _top_values(series, 10)
        if top and not repaired:
            if column == 'abuseipdb_country_code':
                top = [(country_label(value), count) for value, count in top]
            lines.append(
                'Valores mais frequentes: '
                + ', '.join(f'{value} ({count})' for value, count in top)
                + '.'
            )

        documents.append(
            Document(
                id=f'{dataset.key}:column:{column}',
                kind=COLUMN,
                title=f'{column} ({dataset.label})',
                text='\n'.join(lines),
            )
        )
    return documents


def aggregate_documents(df: pd.DataFrame, dataset: Dataset) -> list[Document]:
    documents: list[Document] = []
    documents.extend(_group_documents(df, dataset, 'abuseipdb_country_code', 'país', 25))
    documents.extend(_group_documents(df, dataset, 'abuseipdb_isp', 'ISP (AbuseIPDB)', 25))
    documents.extend(_group_documents(df, dataset, 'virustotal_as_owner', 'proprietário do AS (VirusTotal)', 20))
    documents.extend(_group_documents(df, dataset, 'virustotal_asn', 'ASN (VirusTotal)', 15))
    documents.extend(_score_band_documents(df, dataset))
    documents.extend(_extreme_ip_documents(df, dataset))
    return documents


def _group_documents(df: pd.DataFrame, dataset: Dataset, column: str, label: str, limit: int) -> list[Document]:
    if column not in df.columns or df.empty:
        return []

    working = df.copy()
    working[column] = working[column].astype(str).str.strip().replace({'': 'desconhecido', 'nan': 'desconhecido'})
    if 'score_average_Mobat' in working.columns:
        working['_score_clean'] = to_numeric_clean(working['score_average_Mobat'])
    if 'malicious' in working.columns:
        working['_malicious_clean'] = to_numeric_clean(working['malicious'])
    grouped = working.groupby(column, dropna=False)

    rows = []
    for value, group in grouped:
        row = {
            'valor': value,
            'ips': len(group),
            '%': 100 * len(group) / len(df),
        }
        if '_score_clean' in group.columns:
            numeric = group['_score_clean'].dropna()
            if not numeric.empty:
                row['score_medio'] = numeric.mean()
                row['score_max'] = numeric.max()
        if '_malicious_clean' in group.columns:
            malicious = group['_malicious_clean'].dropna()
            if not malicious.empty:
                row['malicious_medio'] = malicious.mean()
                row['malicious_alto'] = int((malicious >= 90).sum())
        if 'abuseipdb_total_reports' in group.columns:
            reports = pd.to_numeric(group['abuseipdb_total_reports'], errors='coerce').fillna(0)
            row['denuncias'] = reports.sum()
        rows.append(row)

    if not rows:
        return []

    table = pd.DataFrame(rows).sort_values('ips', ascending=False).head(limit)

    lines = [
        f'Agregação por {label} no período {dataset.label} (top {len(table)} de {len(rows)} grupos).',
        f'Contagem de IPs e endereços IP por {label}: responde qual {label} tem mais IPs, '
        f'qual tem menos e como os grupos se distribuem.',
        'Formato: valor | IPs | % do total | score médio | score máx | malicious médio '
        '(escala 0-100) | IPs com malicious >= 90 | denúncias AbuseIPDB.',
    ]
    for _, row in table.iterrows():
        value = row['valor']
        if column == 'abuseipdb_country_code':
            value = country_label(str(value))
        parts = [f"{value} | {int(row['ips'])} IPs | {_fmt_number(row['%'])}%"]
        if 'score_medio' in row:
            parts.append(f"score médio {_fmt_number(row['score_medio'])}")
        if 'score_max' in row:
            parts.append(f"score máx {_fmt_number(row['score_max'])}")
        if 'malicious_medio' in row:
            parts.append(f"malicious médio {_fmt_number(row['malicious_medio'])}")
        if 'malicious_alto' in row:
            parts.append(f"{int(row['malicious_alto'])} com malicious >= 90")
        if 'denuncias' in row:
            parts.append(f"{_fmt_number(row['denuncias'])} denúncias")
        lines.append('- ' + ' | '.join(parts))

    return [
        Document(
            id=f'{dataset.key}:agg:{column}',
            kind=AGGREGATE,
            title=f'{label} – {dataset.label}',
            text='\n'.join(lines),
        )
    ]


def _score_band_documents(df: pd.DataFrame, dataset: Dataset) -> list[Document]:
    if 'score_average_Mobat' not in df.columns:
        return []
    scores = to_numeric_clean(df['score_average_Mobat']).dropna()
    if scores.empty:
        return []

    quantiles = scores.quantile([0.25, 0.5, 0.75, 0.9, 0.99])
    p25, p50, p75, p90 = (float(quantiles.loc[q]) for q in (0.25, 0.5, 0.75, 0.9))

    bands = [
        (f'inferior (<= {p25:.1f})', scores <= p25),
        (f'baixo-médio ({p25:.1f} a {p50:.1f})', (scores > p25) & (scores <= p50)),
        (f'médio-alto ({p50:.1f} a {p75:.1f})', (scores > p50) & (scores <= p75)),
        (f'alto ({p75:.1f} a {p90:.1f})', (scores > p75) & (scores <= p90)),
        (f'muito alto (> {p90:.1f})', scores > p90),
    ]

    lines = [
        f'Distribuição do score_average_Mobat em {dataset.label} '
        f'(total {len(scores)} IPs; média={_fmt_number(scores.mean())}, '
        f'mín={_fmt_number(scores.min())}, máx={_fmt_number(scores.max())}):'
    ]
    for name, mask in bands:
        count = int(mask.sum())
        lines.append(f'- {name}: {count} IPs ({_fmt_number(100 * count / len(scores))}%)')

    lines.append(
        'Percentis: P25={p25}, P50={p50}, P75={p75}, P90={p90}, P99={p99}'.format(
            p25=_fmt_number(quantiles.loc[0.25]),
            p50=_fmt_number(quantiles.loc[0.5]),
            p75=_fmt_number(quantiles.loc[0.75]),
            p90=_fmt_number(quantiles.loc[0.9]),
            p99=_fmt_number(quantiles.loc[0.99]),
        )
    )

    return [
        Document(
            id=f'{dataset.key}:agg:score_bands',
            kind=AGGREGATE,
            title=f'Faixas de score_average_Mobat – {dataset.label}',
            text='\n'.join(lines),
        )
    ]


def _extreme_ip_documents(df: pd.DataFrame, dataset: Dataset) -> list[Document]:
    documents: list[Document] = []
    if 'score_average_Mobat' in df.columns:
        top = df.assign(_score=to_numeric_clean(df['score_average_Mobat']))
        top = top.sort_values('_score', ascending=False).head(20)
        lines = [f'IPs com pior score_average_Mobat em {dataset.label} (maior = pior reputação):']
        for _, row in top.iterrows():
            lines.append(
                f"- {row.get('IP')} | país {row.get('abuseipdb_country_code')} | "
                f"ISP {row.get('abuseipdb_isp')} | score {_fmt_number(row.get('_score'))}"
            )
        documents.append(
            Document(
                id=f'{dataset.key}:agg:worst_ips',
                kind=AGGREGATE,
                title=f'Piores IPs – {dataset.label}',
                text='\n'.join(lines),
            )
        )

    if 'abuseipdb_total_reports' in df.columns and 'IP' in df.columns:
        top = df.assign(_reports=pd.to_numeric(df['abuseipdb_total_reports'], errors='coerce').fillna(0))
        top = top.sort_values('_reports', ascending=False).head(20)
        lines = [f'IPs com mais denúncias no AbuseIPDB em {dataset.label}:']
        for _, row in top.iterrows():
            lines.append(
                f"- {row.get('IP')} | país {row.get('abuseipdb_country_code')} | "
                f"{_fmt_number(row.get('_reports'))} denúncias | "
                f"{_fmt_number(row.get('abuseipdb_num_distinct_users'))} usuários distintos"
            )
        documents.append(
            Document(
                id=f'{dataset.key}:agg:most_reported',
                kind=AGGREGATE,
                title=f'IPs mais denunciados – {dataset.label}',
                text='\n'.join(lines),
            )
        )
    return documents


def row_documents(df: pd.DataFrame, dataset: Dataset) -> list[Document]:
    if df.empty:
        return []

    serialized = _serialize_rows(df)
    if not serialized:
        return []

    chunks = _split_rows(serialized, chunk_target_size(), chunk_overlap(), min_rows_per_chunk())
    documents = [
        Document(
            id=f'{dataset.key}:rows:{index}',
            kind=ROWS,
            title=f'{dataset.label} – linhas {start}-{end}',
            text='\n'.join(chunk),
        )
        for index, (chunk, start, end) in enumerate(chunks)
    ]
    return documents


def _serialize_rows(df: pd.DataFrame) -> list[str]:
    columns = [column for column in df.columns]
    records = df.to_dict(orient='records')
    serialized: list[str] = []
    for record in records:
        parts = []
        for column in columns:
            value = record.get(column)
            if value is None or (isinstance(value, float) and math.isnan(value)):
                continue
            if isinstance(value, str) and value.strip() == '':
                continue
            parts.append(f'{column}: {value}')
        if parts:
            serialized.append('; '.join(parts))
    return serialized


def _split_rows(
    rows: list[str],
    target: int,
    overlap: int,
    min_rows: int,
) -> list[tuple[list[str], int, int]]:
    chunks: list[tuple[list[str], int, int]] = []
    total = len(rows)
    start = 0

    while start < total:
        size = 0
        end = start
        while end < total and (size + len(rows[end]) <= target or end - start < min_rows):
            size += len(rows[end])
            end += 1
        if end == start:
            end = start + 1

        chunks.append((rows[start:end], start + 1, end))
        if end >= total:
            break

        cursor = end - 1
        carried = 0
        overlap_size = 0
        if overlap > 0:
            while cursor > start and (carried == 0 or overlap_size + len(rows[cursor]) <= overlap):
                overlap_size += len(rows[cursor])
                carried += 1
                cursor -= 1

        next_start = end - carried
        start = max(next_start, start + 1)

    return chunks
