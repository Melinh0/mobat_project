from __future__ import annotations

import json

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from mobat_app.rag.datasets import DATASETS
from mobat_app.rag.evaluation import evaluate_index, format_report
from mobat_app.rag.index import get_index


class Command(BaseCommand):
    help = 'Avalia o índice RAG com métricas de IR e testes estatísticos (AUC, Mann-Whitney).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dataset',
            default='4',
            help='Chave do período (1, 2, 3, 4). Padrão: 4 (Total).',
        )
        parser.add_argument('--k', type=int, default=5, help='Profundidade das métricas @k (padrão: 5).')
        parser.add_argument('--json', action='store_true', help='Emite o relatório em JSON.')
        parser.add_argument('--fail-under', type=float, default=None,
                            help='Sai com código 1 se a AUC for menor que o valor informado.')

    def handle(self, *args, **options):
        key = options['dataset']
        if key not in DATASETS:
            raise CommandError(f'Dataset desconhecido: {key} (use {", ".join(DATASETS)})')

        dataset = DATASETS[key]
        self.stdout.write(f'Avaliando {dataset.description} ...')

        try:
            index = get_index(dataset)
        except Exception as exc:  # noqa: BLE001
            raise CommandError(f'Falha ao montar o índice: {exc}') from exc

        report = evaluate_index(
            index,
            k=options['k'],
            threshold=getattr(settings, 'RAG_TFIDF_THRESHOLD', 0.15),
        )

        if options['json']:
            self.stdout.write(json.dumps(report, ensure_ascii=False, indent=2))
        else:
            self.stdout.write(format_report(report))

        auc = report['metrics']['auc']
        fail_under = options['fail_under']
        if fail_under is not None and auc == auc and auc < fail_under:
            raise CommandError(f'AUC {auc:.3f} menor que o mínimo exigido {fail_under:.3f}')

        verdict = report['metrics']['verdict']
        if verdict == 'BOM':
            self.stdout.write(self.style.SUCCESS(f'\nVeredito: {verdict}'))
        else:
            self.stdout.write(self.style.WARNING(f'\nVeredito: {verdict}'))
