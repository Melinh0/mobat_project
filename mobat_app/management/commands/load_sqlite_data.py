import sqlite3
from pathlib import Path
from datetime import datetime
from django.core.management.base import BaseCommand
from mobat_app.models import IPData

def normalize_score(value):
    if value is None or value == '':
        return None
    if isinstance(value, (int, float)):
        return round(float(value), 1)
    if isinstance(value, str):
        s = value.strip()
        if '.' not in s:
            try:
                return round(float(s), 1)
            except:
                return None
        parts = s.split('.')
        if len(parts) >= 2:
            integer_part = parts[0]
            decimal_part = ''.join(parts[1:])
            num_str = integer_part + '.' + decimal_part
            try:
                return round(float(num_str), 1)
            except:
                return None
        try:
            return round(float(s.replace('.', '')), 1)
        except:
            return None
    return None

class Command(BaseCommand):
    help = 'Carrega dados de todos os bancos SQLite para o PostgreSQL (preservando séries temporais)'

    def handle(self, *args, **options):
        seasons_dir = Path('mobat_app/Seasons')
        if not seasons_dir.exists():
            self.stdout.write(self.style.ERROR(f'Pasta Seasons não encontrada em {seasons_dir}'))
            return

        db_files = list(seasons_dir.glob('*.sqlite')) + list(seasons_dir.glob('*.db'))
        if not db_files:
            self.stdout.write(self.style.WARNING('Nenhum arquivo .sqlite ou .db encontrado em Seasons'))
            return

        column_mapping = {
            'IP': 'IP',
            'abuseipdb_is_whitelisted': 'abuseipdb_is_whitelisted',
            'abuseipdb_confidence_score': 'abuseipdb_confidence_score',
            'abuseipdb_country_code': 'abuseipdb_country_code',
            'abuseipdb_isp': 'abuseipdb_isp',
            'abuseipdb_domain': 'abuseipdb_domain',
            'abuseipdb_total_reports': 'abuseipdb_total_reports',
            'abuseipdb_num_distinct_users': 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at': 'abuseipdb_last_reported_at',
            'virustotal_reputation': 'virustotal_reputation',
            'virustotal_regional_internet_registry': 'virustotal_regional_internet_registry',
            'virustotal_as_owner': 'virustotal_as_owner',
            'harmless': 'harmless',
            'malicious': 'malicious',
            'suspicious': 'suspicious',
            'undetected': 'undetected',
            'IBM_score': 'IBM_score',
            'IBM_average history Score': 'IBM_average_history_Score',
            'IBM_most common score': 'IBM_most_common_score',
            'virustotal_asn': 'virustotal_asn',
            'SHODAN_asn': 'SHODAN_asn',
            'SHODAN_isp': 'SHODAN_isp',
            'ALIENVAULT_reputation': 'ALIENVAULT_reputation',
            'ALIENVAULT_asn': 'ALIENVAULT_asn',
            'score_average_Mobat': 'score_average_Mobat',
        }

        total_registros = 0
        valid_semesters = ['PrimeiroSemestre', 'SegundoSemestre', 'TerceiroSemestre', 'Total']

        for db_path in db_files:
            semester_name = db_path.stem
            if semester_name not in valid_semesters:
                self.stdout.write(self.style.WARNING(f'Arquivo {db_path.name} ignorado (nome inválido)'))
                continue

            self.stdout.write(f'Carregando {semester_name}...')

            sqlite_conn = sqlite3.connect(str(db_path))
            sqlite_conn.row_factory = sqlite3.Row
            sqlite_cursor = sqlite_conn.cursor()

            table_name = semester_name
            sqlite_cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
            if not sqlite_cursor.fetchone():
                self.stdout.write(self.style.WARNING(f'Tabela {table_name} não encontrada em {db_path.name}'))
                sqlite_conn.close()
                continue

            sqlite_cursor.execute(f"SELECT * FROM {table_name}")
            rows = sqlite_cursor.fetchall()
            count = 0

            for row in rows:
                data = {}
                for sqlite_col, model_col in column_mapping.items():
                    if sqlite_col in row.keys():
                        value = row[sqlite_col]

                        if isinstance(value, str):
                            lower_val = value.strip().lower()
                            if lower_val == 'none':
                                value = None
                            elif model_col == 'abuseipdb_is_whitelisted':
                                if lower_val == 'true':
                                    value = True
                                elif lower_val == 'false':
                                    value = False
                                else:
                                    value = None

                        if model_col == 'abuseipdb_last_reported_at' and value is not None:
                            if isinstance(value, str):
                                try:
                                    value = datetime.fromisoformat(value.replace('Z', '+00:00'))
                                except:
                                    value = None

                        if model_col == 'score_average_Mobat':
                            value = normalize_score(value)
                        else:
                            if model_col in ['abuseipdb_confidence_score', 'abuseipdb_total_reports',
                                             'abuseipdb_num_distinct_users', 'virustotal_reputation',
                                             'harmless', 'malicious', 'suspicious', 'undetected',
                                             'IBM_score', 'IBM_most_common_score', 'ALIENVAULT_reputation']:
                                if value is not None and value != '':
                                    try:
                                        value = int(float(str(value).replace('.', '').split('.')[0]))
                                    except:
                                        value = None
                            elif model_col == 'IBM_average_history_Score':
                                if value is not None and value != '':
                                    try:
                                        value = float(str(value).replace(',', '.'))
                                    except:
                                        value = None

                        data[model_col] = value

                data['semester'] = semester_name

                if not data.get('IP'):
                    continue

                try:
                    IPData.objects.create(**data)
                    count += 1
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'Erro no IP {data["IP"]}: {str(e)[:200]}'))
                    continue

            sqlite_conn.close()
            self.stdout.write(self.style.SUCCESS(f'  {count} registros inseridos em {semester_name}'))
            total_registros += count

        self.stdout.write(self.style.SUCCESS(f'\n✅ Total de registros inseridos: {total_registros}'))