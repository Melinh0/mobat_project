from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

import pandas as pd

from ..utils.ollama_client import OllamaClient, OllamaError
from .corpus import _fmt_number
from .datasets import COLUMN_HELP, Dataset
from .sandbox import SandboxResult, run_pandas_code

logger = logging.getLogger(__name__)

MAX_ROUNDS = 2
SAMPLE_ROWS = 3

CODE_SYSTEM_PROMPT = """Você é um analista de dados que escreve código pandas.
Você receberá uma pergunta sobre uma tabela de reputação de IPs e deve responder
APENAS com um objeto JSON no formato:

{"code": "<código pandas em python>", "reason": "<frase curta em pt-br>"}

Regras do código:
- A tabela já está carregada na variável `df` (pandas.DataFrame); `pd` e `np` também existem.
- Algumas colunas chegam como texto corrompido (ex.: score_average_Mobat com separador de
  milhar sobre o decimal). Use `clean_number(df['coluna'])` para obter a série numérica
  tratada antes de agregar, e faça a conversão ANTES de calcular médias/máximos.
- Colunas do VirusTotal (harmless, malicious, suspicious, undetected) são escala 0-100.
- NÃO use import, open, funções definidas por você, try/with/lambda nem leitura de arquivos.
- Atribua sempre o resultado final à variável `result` (número, string, lista, dict, Series ou DataFrame).
- Use apenas colunas que existem na tabela (veja a lista de colunas abaixo).
- Prefira agregações objetivas: contagens, somas, médias, valores máximos/mínimos, groupby, value_counts.
- Ao agregar por grupo (país, ISP, ASN, faixa), devolva também o tamanho da amostra
  (ex.: ``df.groupby('pais')['score'].agg(['mean', 'count'])``), para que comparações
  entre médias mostrem quantos IPs sustentam cada número.
- Mantenha `result` compacto: no máximo ~12 linhas (ordene e corte com `.head()`
  ou devolva um resumo), porque o resultado vai inteiro para o prompt final.
- Se a pergunta não precisar de cálculo (saudação, explicação conceitual), responda {"code": "", "reason": "..."}.
- Responda somente com o JSON, sem comentários e sem cercas de código."""


@dataclass
class AnalysisResult:

    attempted: bool = False
    code: str | None = None
    output: str | None = None
    error: str | None = None
    rounds: int = 0
    reason: str = ''
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.output) and not self.error

    def as_prompt_block(self) -> str:
        if not self.attempted:
            return '(nenhuma agregação executada para esta pergunta)'
        lines = []
        if self.reason:
            lines.append(f'Intenção do analista: {self.reason}')
        if self.code:
            lines.append('Código executado:\n```python\n' + self.code + '\n```')
        if self.output:
            lines.append('Resultado calculado sobre a base:\n' + self.output)
        if self.error:
            lines.append(
                'Agregação NÃO concluiu (considere apenas os documentos de contexto): '
                + self.error
            )
        return '\n'.join(lines) or '(nenhum resultado)'


def dataframe_schema(df: pd.DataFrame) -> str:
    lines = []
    for column in df.columns:
        series = df[column]
        sample = series.dropna().astype(str).head(SAMPLE_ROWS).tolist()
        help_text = COLUMN_HELP.get(column, '')
        lines.append(
            f'- {column} ({series.dtype})'
            + (f' – {help_text}' if help_text else '')
            + (f' | exemplos: {", ".join(sample)}' if sample else '')
        )
    return '\n'.join(lines)


def analyse(
    question: str,
    df: pd.DataFrame,
    dataset: Dataset,
    client: OllamaClient | None = None,
    model: str | None = None,
    temperature: float = 0.0,
    timeout: float = 10.0,
) -> AnalysisResult:
    from ..utils.ollama_client import get_client

    client = client or get_client()
    result = AnalysisResult(attempted=True)

    schema = dataframe_schema(df)
    messages = [
        {'role': 'system', 'content': CODE_SYSTEM_PROMPT},
        {
            'role': 'user',
            'content': (
                f'Período analisado: {dataset.label} ({len(df)} linhas).\n\n'
                f'Colunas da tabela:\n{schema}\n\n'
                f'Pergunta: {question}'
            ),
        },
    ]

    last_error: str | None = None

    for round_number in range(1, MAX_ROUNDS + 1):
        result.rounds = round_number

        if last_error:
            messages.append(
                {
                    'role': 'user',
                    'content': (
                        f'O código falhou com o erro: {last_error}\n'
                        'Corrija e devolva o JSON novamente, com o mesmo formato.'
                    ),
                }
            )

        try:
            raw = client.chat_text(
                messages,
                model=model,
                temperature=temperature,
                json_format=True,
            )
        except OllamaError as exc:
            result.error = f'Falha ao consultar o modelo: {exc}'
            logger.warning('analyst: %s', result.error)
            return result

        payload = _parse_json(raw)
        if payload is None:
            last_error = 'a resposta não era um JSON válido'
            messages.append({'role': 'assistant', 'content': raw[:1000]})
            continue

        code = (payload.get('code') or '').strip()
        result.reason = (payload.get('reason') or '').strip()
        result.code = code or None
        messages.append({'role': 'assistant', 'content': raw[:2000]})

        if not code:
            result.output = None
            result.error = None
            return result

        sandbox_result: SandboxResult = run_pandas_code(code, df, timeout=timeout)
        if sandbox_result.ok:
            result.output = sandbox_result.output
            result.error = None
            result.notes = sandbox_result.notes
            return result

        last_error = sandbox_result.error
        result.error = sandbox_result.error

    result.error = last_error or result.error
    return result


def _parse_json(raw: str) -> dict | None:
    text = (raw or '').strip()
    if text.startswith('```'):
        text = text.strip('`')
        if text.startswith('json'):
            text = text[4:]
    text = text.strip()
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        start, end = text.find('{'), text.rfind('}')
        if start == -1 or end <= start:
            return None
        try:
            payload = json.loads(text[start:end + 1])
        except (json.JSONDecodeError, ValueError):
            return None
    return payload if isinstance(payload, dict) else None


def quick_stats(df: pd.DataFrame) -> str:
    total = len(df)
    lines = [f'linhas={total}']
    if 'score_average_Mobat' in df.columns:
        scores = pd.to_numeric(df['score_average_Mobat'], errors='coerce').dropna()
        if not scores.empty:
            lines.append(
                f"score_average_Mobat médio={_fmt_number(scores.mean())} "
                f"máx={_fmt_number(scores.max())}"
            )
    if 'abuseipdb_country_code' in df.columns:
        top = df['abuseipdb_country_code'].astype(str).value_counts().head(3)
        lines.append('países top: ' + ', '.join(f'{c}={int(n)}' for c, n in top.items()))
    return ' | '.join(lines)
