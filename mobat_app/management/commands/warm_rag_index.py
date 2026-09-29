from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from mobat_app.rag.datasets import DATASETS
from mobat_app.rag.index import get_index


class Command(BaseCommand):
    help = 'Indexa os dados tabulares (Seasons/Sheets) para o chatbot RAG.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dataset',
            default='all',
            help='Chave do período (1, 2, 3, 4) ou "all" (padrão).',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Reconstrói mesmo se o índice já estiver em cache.',
        )

    def handle(self, *args, **options):
        key = options['dataset']
        if key == 'all':
            keys = list(DATASETS)
        elif key in DATASETS:
            keys = [key]
        else:
            raise CommandError(f'Dataset desconhecido: {key} (use {", ".join(DATASETS)} ou "all")')

        for dataset_key in keys:
            dataset = DATASETS[dataset_key]
            self.stdout.write(f'Indexando {dataset.description} ...')
            try:
                index = get_index(dataset, force=options['force'])
            except Exception as exc:  # noqa: BLE001
                raise CommandError(f'Falha ao indexar {dataset.description}: {exc}') from exc
            self.stdout.write(self.style.SUCCESS(f'  OK: {index.size} documentos'))
