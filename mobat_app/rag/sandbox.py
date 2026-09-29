from __future__ import annotations

import ast
import sys
import threading
import time
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .numeric import to_numeric_clean

MAX_CODE_LENGTH = 4000
MAX_AST_NODES = 600
DEFAULT_TIMEOUT = 10.0
MAX_OUTPUT_CHARS = 4000

ALLOWED_NODES: tuple = (
    ast.Module, ast.Expr, ast.Assign, ast.AugAssign, ast.AnnAssign,
    ast.If, ast.For, ast.While, ast.Break, ast.Continue, ast.Pass,
    ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare, ast.IfExp,
    ast.Call, ast.keyword, ast.Constant, ast.Name, ast.Attribute,
    ast.Subscript, ast.Slice, ast.Starred,
    ast.List, ast.Tuple, ast.Dict, ast.Set,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.comprehension,
    ast.JoinedStr, ast.FormattedValue,
    ast.Load, ast.Store,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.LShift, ast.RShift, ast.BitOr, ast.BitXor, ast.BitAnd,
    ast.And, ast.Or, ast.Not, ast.UAdd, ast.USub, ast.Invert,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
    ast.Is, ast.IsNot, ast.In, ast.NotIn,
)

FORBIDDEN_NODES: tuple = (
    ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal,
    ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
    ast.Return, ast.Yield, ast.YieldFrom, ast.Await,
    ast.Raise, ast.Try, ast.Assert, ast.With, ast.AsyncWith, ast.AsyncFor,
    ast.Delete, ast.Match, ast.NamedExpr,
)

SAFE_BUILTINS: dict = {
    'len': len, 'abs': abs, 'min': min, 'max': max, 'sum': sum,
    'round': round, 'sorted': sorted, 'reversed': reversed,
    'list': list, 'dict': dict, 'set': set, 'tuple': tuple,
    'str': str, 'int': int, 'float': float, 'bool': bool,
    'enumerate': enumerate, 'zip': zip, 'range': range,
    'any': any, 'all': all, 'format': format, 'print': print,
    'isinstance': isinstance, 'repr': repr,
    'ValueError': ValueError, 'KeyError': KeyError, 'TypeError': TypeError,
    'IndexError': IndexError, 'ZeroDivisionError': ZeroDivisionError,
    'AttributeError': AttributeError, 'StopIteration': StopIteration,
}

BLOCKED_NAMES: frozenset[str] = frozenset({
    'open', 'eval', 'exec', 'compile', '__import__', 'input', 'breakpoint',
    'globals', 'locals', 'vars', 'dir', 'getattr', 'setattr', 'delattr',
    'type', 'object', 'super', 'help', 'memoryview', 'id', 'hash', 'callable',
    'bytearray', 'bytes', 'frozenset', 'property', 'classmethod', 'staticmethod',
    'exit', 'quit',
})

BLOCKED_ATTRIBUTES: frozenset[str] = frozenset({
    'eval', 'exec', 'compile', 'system', 'popen', 'remove', 'unlink', 'rmdir',
    'chmod', 'chown', 'kill', 'spawn', 'fork', 'dumps', 'loads',
    'read_pickle', 'to_pickle', 'read_html', 'read_sql', 'read_sql_query',
    'read_csv', 'read_excel', 'to_clipboard', 'to_pickle',
})

SAFE_GLOBAL_NAMES: frozenset[str] = frozenset({'df', 'pd', 'np', 'result', 'clean_number'}) | frozenset(SAFE_BUILTINS)


class SandboxError(Exception):
    pass


class SandboxTimeout(SandboxError):
    pass


@dataclass
class SandboxResult:
    ok: bool
    output: str = ''
    error: str | None = None
    code: str = ''
    duration: float = 0.0
    notes: list[str] = field(default_factory=list)


def _validate(tree: ast.Module) -> None:
    node_count = sum(1 for _ in ast.walk(tree))
    if node_count > MAX_AST_NODES:
        raise SandboxError(f'Código complexo demais ({node_count} nós; máximo {MAX_AST_NODES})')

    assigned = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    }
    allowed_names = SAFE_GLOBAL_NAMES | assigned

    for node in ast.walk(tree):
        if isinstance(node, FORBIDDEN_NODES):
            raise SandboxError(f'Construção não permitida: {type(node).__name__}')
        if not isinstance(node, ALLOWED_NODES):
            raise SandboxError(f'Construção não permitida: {type(node).__name__}')

        if isinstance(node, ast.Name):
            if node.id.startswith('__'):
                raise SandboxError(f'Nome proibido: {node.id}')
            if isinstance(node.ctx, ast.Load) and node.id not in allowed_names:
                raise SandboxError(f'Nome não disponível no sandbox: {node.id}')

        if isinstance(node, ast.Attribute):
            if node.attr.startswith('_'):
                raise SandboxError(f'Atributo proibido: {node.attr}')
            if node.attr in BLOCKED_ATTRIBUTES:
                raise SandboxError(f'Atributo bloqueado: {node.attr}')

        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and (func.id in BLOCKED_NAMES or func.id not in allowed_names):
                raise SandboxError(f'Função não permitida: {func.id}')
            if isinstance(func, ast.Attribute) and func.attr.startswith('_'):
                raise SandboxError('Chamada a atributo privado bloqueada')


def run_pandas_code(
    code: str,
    df: pd.DataFrame,
    timeout: float = DEFAULT_TIMEOUT,
    max_output: int = MAX_OUTPUT_CHARS,
) -> SandboxResult:
    started = time.monotonic()

    code = (code or '').strip()
    if not code:
        return SandboxResult(ok=False, error='Nenhum código para executar', code=code)
    if len(code) > MAX_CODE_LENGTH:
        return SandboxResult(
            ok=False,
            error=f'Código longo demais ({len(code)} caracteres; máximo {MAX_CODE_LENGTH})',
            code=code,
        )

    try:
        tree = ast.parse(code, mode='exec')
        _validate(tree)
        if tree.body and isinstance(tree.body[-1], ast.Expr):
            last = tree.body[-1]
            tree.body[-1] = ast.Assign(
                targets=[ast.Name(id='result', ctx=ast.Store())],
                value=last.value,
            )
            ast.fix_missing_locations(tree)
        compiled = compile(tree, '<ollama-pandas>', 'exec')
    except SyntaxError as exc:
        return SandboxResult(ok=False, error=f'Erro de sintaxe: {exc}', code=code)
    except SandboxError as exc:
        return SandboxResult(ok=False, error=f'Código recusado: {exc}', code=code)

    namespace: dict = {
        '__builtins__': SAFE_BUILTINS,
        'pd': pd,
        'np': np,
        'df': df.copy(deep=True),
        'result': None,
        'clean_number': to_numeric_clean,
    }

    deadline = time.monotonic() + timeout
    errors: list[str] = []
    finished = threading.Event()

    def tracer(frame, event, arg):
        if time.monotonic() > deadline:
            raise SandboxTimeout(f'Execução excedeu o tempo limite de {timeout:.0f}s')
        return tracer

    def worker() -> None:
        sys.settrace(tracer)
        try:
            exec(compiled, namespace)  # noqa: S102
        except SandboxTimeout as exc:
            errors.append(str(exc))
        except Exception as exc:  # noqa: BLE001
            errors.append(f'{type(exc).__name__}: {exc}')
        finally:
            sys.settrace(None)
            finished.set()

    thread = threading.Thread(target=worker, name='pandas-sandbox', daemon=True)
    thread.start()
    thread.join(timeout + 1.0)

    duration = time.monotonic() - started

    if not finished.is_set():
        return SandboxResult(
            ok=False,
            error=f'Execução excedeu o tempo limite de {timeout:.0f}s',
            code=code,
            duration=duration,
        )
    if errors:
        return SandboxResult(ok=False, error=errors[0], code=code, duration=duration)

    try:
        output = format_value(namespace.get('result'), max_output)
    except Exception as exc:  # noqa: BLE001
        return SandboxResult(
            ok=False,
            error=f'Não foi possível formatar o resultado: {exc}',
            code=code,
            duration=duration,
        )

    if not output:
        output = '(código executado sem retorno)'
        notes = ['o código não retornou um valor; atribua o resultado a `result`']
    else:
        notes = []

    return SandboxResult(ok=True, output=output, code=code, duration=duration, notes=notes)


def format_value(value, max_output: int = MAX_OUTPUT_CHARS) -> str:
    if value is None:
        return ''
    if isinstance(value, pd.DataFrame):
        if value.empty:
            return '(DataFrames vazio)'
        head = value.head(80)
        default_index = value.index.equals(pd.RangeIndex(len(value)))
        text = head.to_string(index=not default_index)
        if len(value) > 80:
            text += f'\n... ({len(value) - 80} linhas omitidas de {len(value)})'
    elif isinstance(value, pd.Series):
        text = value.head(80).to_string()
        if len(value) > 80:
            text += f'\n... ({len(value) - 80} itens omitidos de {len(value)})'
    elif isinstance(value, (list, tuple)):
        items = list(value)
        text = ', '.join(str(item) for item in items[:80])
        if len(items) > 80:
            text += f' ... ({len(items) - 80} itens omitidos de {len(items)})'
    elif isinstance(value, dict):
        items = list(value.items())[:80]
        text = '; '.join(f'{key}: {item}' for key, item in items)
        if len(value) > 80:
            text += f'; ... ({len(value) - 80} itens omitidos de {len(value)})'
    elif isinstance(value, (np.integer,)):
        text = str(int(value))
    elif isinstance(value, (np.floating, float)):
        number = float(value)
        text = str(int(number)) if number.is_integer() else f'{number:.6g}'
    elif isinstance(value, (np.bool_, bool)):
        text = 'true' if bool(value) else 'false'
    else:
        text = str(value)

    text = text.strip()
    if len(text) > max_output:
        text = text[:max_output] + '\n... (saída truncada)'
    return text
