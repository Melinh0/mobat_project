from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd
from django.conf import settings

BASE_DIR: Path = Path(settings.BASE_DIR)
SEASONS_DIR = BASE_DIR / 'mobat_app' / 'Seasons'
SHEETS_DIR = BASE_DIR / 'mobat_app' / 'Sheets'

PERIOD_LABELS = {
    '1': 'Abril-Maio(2023)',
    '2': 'Setembro-Novembro(2023)',
    '3': 'Janeiro-Março(2024)',
    '4': 'Total-Coletado',
}


@dataclass(frozen=True)
class Dataset:

    key: str
    label: str
    sqlite_file: str
    table: str
    sheet_file: str

    @property
    def sqlite_path(self) -> Path:
        return SEASONS_DIR / self.sqlite_file

    @property
    def sheet_path(self) -> Path:
        return SHEETS_DIR / self.sheet_file

    @property
    def description(self) -> str:
        return f"{self.label} – tabela {self.table}"


DATASETS: dict[str, Dataset] = {
    '1': Dataset('1', PERIOD_LABELS['1'], 'PrimeiroSemestre.sqlite', 'PrimeiroSemestre', 'PrimeiroSemestre2023.xlsx'),
    '2': Dataset('2', PERIOD_LABELS['2'], 'SegundoSemestre.sqlite', 'SegundoSemestre', 'SegundoSemestre2023.xlsx'),
    '3': Dataset('3', PERIOD_LABELS['3'], 'TerceiroSemestre.sqlite', 'TerceiroSemestre', 'PrimeiroSemestre2024.xlsx'),
    '4': Dataset('4', PERIOD_LABELS['4'], 'Total.sqlite', 'Total', 'Total.xlsx'),
}

DEFAULT_DATASET_KEY = '4'


COLUMN_HELP: dict[str, str] = {
    'IP': 'endereço IPv4 observado na coleta',
    'abuseipdb_is_whitelisted': 'se o IP está na lista branca do AbuseIPDB (true/false)',
    'abuseipdb_confidence_score': 'score de confiança de abuso do AbuseIPDB (0-100)',
    'abuseipdb_country_code': 'país (ISO alpha-2) segundo AbuseIPDB',
    'abuseipdb_isp': 'provedor de internet (ISP) segundo AbuseIPDB',
    'abuseipdb_domain': 'domínio associado ao IP no AbuseIPDB',
    'abuseipdb_total_reports': 'total de denúncias recebidas no AbuseIPDB',
    'abuseipdb_num_distinct_users': 'usuários distintos que denunciaram o IP',
    'abuseipdb_last_reported_at': 'data/hora da última denúncia',
    'virustotal_reputation': 'reputação do IP no VirusTotal (negativo = ruim)',
    'virustotal_regional_internet_registry': 'RIR responsável pelo bloco (ARIN, RIPE, LACNIC...)',
    'virustotal_as_owner': 'proprietário do sistema autônomo (AS) no VirusTotal',
    'harmless': 'percentual (0-100) de avaliações "harmless" no VirusTotal',
    'malicious': 'percentual (0-100) de avaliações "malicious" no VirusTotal',
    'suspicious': 'percentual (0-100) de avaliações "suspicious" no VirusTotal',
    'undetected': 'percentual (0-100) de avaliações "undetected" no VirusTotal',
    'IBM_score': 'score de risco atribuído pela IBM X-Force',
    'IBM_average history Score': 'média histórica do score da IBM X-Force',
    'IBM_most common score': 'score mais comum da IBM X-Force',
    'virustotal_asn': 'número do sistema autônomo (ASN) no VirusTotal',
    'SHODAN_asn': 'ASN segundo o Shodan',
    'SHODAN_isp': 'ISP segundo o Shodan',
    'ALIENVAULT_reputation': 'reputação no AlienVault OTX (negativo = ruim)',
    'ALIENVAULT_asn': 'ASN segundo o AlienVault OTX',
    'score_average_Mobat': 'média dos scores das fontes (métrica própria da ferramenta, quanto maior pior); '
                           'em parte dos períodos está gravada como texto com separador de milhar e é '
                           'reparada automaticamente pelos agregados',
}

COUNTRY_HELP = 'código de país ISO alpha-2 (ex.: BR = Brasil, RU = Rússia, US = Estados Unidos)'

COUNTRY_NAMES_PT: dict[str, str] = {
    'BR': 'Brasil', 'US': 'Estados Unidos', 'RU': 'Rússia', 'CN': 'China',
    'DE': 'Alemanha', 'FR': 'França', 'IN': 'Índia', 'GB': 'Reino Unido',
    'UK': 'Reino Unido', 'NL': 'Holanda', 'UA': 'Ucrânia', 'VN': 'Vietnã',
    'ID': 'Indonésia', 'KR': 'Coreia do Sul', 'JP': 'Japão', 'PL': 'Polônia',
    'TR': 'Turquia', 'IR': 'Irã', 'IQ': 'Iraque', 'IL': 'Israel',
    'AR': 'Argentina', 'MX': 'México', 'CO': 'Colômbia', 'CL': 'Chile',
    'PE': 'Peru', 'VE': 'Venezuela', 'EC': 'Equador', 'BO': 'Bolívia',
    'UY': 'Uruguai', 'PY': 'Paraguai', 'ES': 'Espanha', 'IT': 'Itália',
    'PT': 'Portugal', 'CA': 'Canadá', 'AU': 'Austrália', 'ZA': 'África do Sul',
    'NG': 'Nigéria', 'EG': 'Egito', 'KE': 'Quênia',
    'SE': 'Suécia', 'NO': 'Noruega', 'FI': 'Finlândia', 'DK': 'Dinamarca',
    'CH': 'Suíça', 'AT': 'Áustria', 'BE': 'Bélgica', 'RO': 'Romênia',
    'CZ': 'Tchéquia', 'GR': 'Grécia', 'HU': 'Hungria', 'BG': 'Bulgária',
    'RS': 'Sérvia', 'SK': 'Eslováquia', 'SI': 'Eslovênia', 'HR': 'Croácia',
    'LT': 'Lituânia', 'LV': 'Letônia', 'EE': 'Estônia', 'IE': 'Irlanda',
    'TH': 'Tailândia', 'MY': 'Malásia', 'PH': 'Filipinas', 'PK': 'Paquistão',
    'BD': 'Bangladesh', 'KZ': 'Cazaquistão', 'GE': 'Geórgia', 'AM': 'Armênia',
    'AZ': 'Azerbaijão', 'MD': 'Moldávia', 'BY': 'Bielorrússia', 'CY': 'Chipre',
    'MT': 'Malta', 'LU': 'Luxemburgo', 'IS': 'Islândia', 'AL': 'Albânia',
    'MK': 'Macedônia do Norte', 'BA': 'Bósnia e Herzegovina', 'ME': 'Montenegro',
    'QA': 'Catar', 'AE': 'Emirados Árabes Unidos', 'SA': 'Arábia Saudita',
    'KW': 'Kuwait', 'OM': 'Omã', 'JO': 'Jordânia', 'LB': 'Líbano',
    'LK': 'Sri Lanka', 'MM': 'Mianmar', 'KH': 'Cambodja', 'LA': 'Laos',
    'MN': 'Mongólia', 'TW': 'Taiwan', 'HK': 'Hong Kong', 'SG': 'Singapura',
    'NZ': 'Nova Zelândia', 'GH': 'Gana', 'TZ': 'Tanzânia', 'ET': 'Etiópia',
    'MA': 'Marrocos', 'DZ': 'Argélia', 'TN': 'Tunísia', 'LY': 'Líbia',
    'SD': 'Sudão', 'ZW': 'Zimbábue', 'ZM': 'Zâmbia', 'AO': 'Angola',
    'MZ': 'Moçambique', 'CM': 'Camarões', 'CI': 'Costa do Marfim',
    'SN': 'Senegal', 'CD': 'República Democrática do Congo',
    'DO': 'República Dominicana', 'CU': 'Cuba', 'GT': 'Guatemala',
    'PA': 'Panamá', 'CR': 'Costa Rica', 'HN': 'Honduras', 'SV': 'El Salvador',
    'NI': 'Nicarágua', 'PR': 'Porto Rico', 'JM': 'Jamaica', 'TT': 'Trinidad e Tobago',
}


def country_label(code: str) -> str:
    cleaned = (code or '').strip()
    if len(cleaned) != 2 or not cleaned.isalpha():
        return cleaned
    upper = cleaned.upper()
    name = COUNTRY_NAMES_PT.get(upper)
    if not name:
        try:
            import pycountry

            record = pycountry.countries.get(alpha_2=upper)
            name = record.name if record else None
        except Exception:  # noqa: BLE001
            name = None
    return f'{upper} ({name})' if name else upper


def dataset_from_session(session) -> Dataset:
    key = session.get('table_choice') or DEFAULT_DATASET_KEY
    if str(key) not in DATASETS:
        db_path = session.get('db_path') or ''
        for dataset in DATASETS.values():
            if db_path.endswith(dataset.sqlite_file):
                return dataset
        key = DEFAULT_DATASET_KEY
    return DATASETS[str(key)]


def load_dataframe(dataset: Dataset) -> pd.DataFrame:
    df = _load_sqlite(dataset)
    if df is None:
        df = _load_sheet(dataset)
    if df is None:
        raise FileNotFoundError(
            f"Não foi possível carregar o dataset {dataset.description} "
            f"(procurado em {dataset.sqlite_path} e {dataset.sheet_path})"
        )
    return df.reset_index(drop=True)


def _load_sqlite(dataset: Dataset) -> pd.DataFrame | None:
    path = dataset.sqlite_path
    if not path.is_file():
        return None
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return pd.read_sql_query(f'SELECT * FROM "{dataset.table}"', conn)
    except (sqlite3.Error, pd.errors.DatabaseError):
        return None
    finally:
        conn.close()


def _load_sheet(dataset: Dataset) -> pd.DataFrame | None:
    path = dataset.sheet_path
    if not path.is_file():
        return None
    try:
        return pd.read_excel(path)
    except ValueError:
        return None


def dataframe_fingerprint(dataset: Dataset) -> tuple:
    parts: list = [dataset.key]
    for path in (dataset.sqlite_path, dataset.sheet_path):
        try:
            stat = path.stat()
            parts.append((path.name, stat.st_mtime_ns, stat.st_size))
        except OSError:
            parts.append((path.name, 0, 0))
    return tuple(parts)
