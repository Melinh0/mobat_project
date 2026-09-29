from __future__ import annotations

import base64
import json
import re
import sqlite3
import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock

import pandas as pd
from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from mobat_app.rag import service
from mobat_app.rag.analyst import analyse, dataframe_schema
from mobat_app.rag.corpus import (
    AGGREGATE,
    COLUMN,
    OVERVIEW,
    ROWS,
    _split_rows,
    build_documents,
)
from mobat_app.rag.datasets import DATASETS, country_label, dataset_from_session
from mobat_app.rag.evaluation import evaluate_index, format_report
from mobat_app.rag.index import VectorIndex, clear_cache
from mobat_app.rag.sandbox import SandboxResult, run_pandas_code
from mobat_app.rag.stats import clear_cache as clear_stats_cache
from mobat_app.rag.stats import statistical_summary
from mobat_app.utils.ml_helpers import categorize_non_numeric_columns, plot_feature_importance
from mobat_app.utils.ollama_client import OllamaClient, OllamaError, OllamaRateLimited
from mobat_project.env import load_env


def fixture_dataframe(br_rows: int = 12, ru_rows: int = 8, us_rows: int = 5) -> pd.DataFrame:
    rows = []

    def add(country: str, isp: str, score: float, malicious: int, reports: int) -> None:
        rows.append({
            'IP': f'200.0.0.{len(rows) + 1}',
            'abuseipdb_country_code': country,
            'abuseipdb_isp': isp,
            'abuseipdb_total_reports': reports,
            'abuseipdb_num_distinct_users': max(1, reports // 2),
            'virustotal_as_owner': f'AS-{isp}',
            'virustotal_asn': f'650{len(rows) % 7}0',
            'malicious': malicious,
            'suspicious': 0,
            'harmless': 20,
            'score_average_Mobat': score,
        })

    for index in range(br_rows):
        add('BR', 'Operadora BR', 0.4 + (index % 5) * 0.3, malicious=index % 3, reports=index)
    for index in range(ru_rows):
        add('RU', 'Host RU', 1.2 + (index % 4) * 0.4, malicious=2, reports=10 + index)
    for index in range(us_rows):
        add('US', 'Cloud US', 0.2, malicious=0, reports=1)

    return pd.DataFrame(rows)


class FakeOllamaClient:

    default_model = 'modelo-fake'

    def __init__(self, code: str | None = None, final_answer: str = 'Resposta final.'):
        self.code = code
        self.final_answer = final_answer
        self.calls: list[dict] = []

    def chat_text(self, messages, **kwargs):
        self.calls.append({'messages': messages, **kwargs})
        if kwargs.get('json_format'):
            payload = {
                'code': self.code or "result = int((df['abuseipdb_country_code'] == 'BR').sum())",
                'reason': 'contar IPs do Brasil',
            }
            return json.dumps(payload)
        return self.final_answer


class EnvLoaderTests(SimpleTestCase):
    def test_load_env_reads_file_and_respects_existing_vars(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.env'
            path.write_text(
                '# comentário\n'
                'OLLAMA_HOST=https://ollama.com\n'
                'OLLAMA_MAX_TOKENS=16000\n'
                'QUOTED="valor com espaço"\n'
                'JAH_EXISTE=do_ambiente\n'
                'SEM_IGUAL\n',
                encoding='utf-8',
            )
            with self.settings():
                import os

                os.environ.pop('JAH_EXISTE', None)
                loaded = load_env(path)
                self.assertEqual(loaded['OLLAMA_HOST'], 'https://ollama.com')
                self.assertEqual(loaded['OLLAMA_MAX_TOKENS'], '16000')
                self.assertEqual(loaded['QUOTED'], 'valor com espaço')
                self.assertNotIn('SEM_IGUAL', loaded)
                os.environ['JAH_EXISTE'] = 'do_ambiente'
                loaded = load_env(path)
                self.assertEqual(loaded['JAH_EXISTE'], 'do_ambiente')
                os.environ.pop('JAH_EXISTE', None)

    def test_missing_file_returns_empty(self):
        self.assertEqual(load_env('/caminho/inexistente/.env'), {})

    def test_project_env_is_loaded(self):
        from django.conf import settings

        self.assertTrue(settings.OllamaHost if hasattr(settings, 'OllamaHost') else settings.OLLAMA_HOST)
        self.assertGreaterEqual(len(settings.OLLAMA_API_KEYS), 1)
        self.assertEqual(settings.OLLAMA_DEFAULT_MODEL, 'gemma4:cloud')
        self.assertEqual(settings.OLLAMA_MAX_TOKENS, 16000)


class CorpusTests(SimpleTestCase):
    def setUp(self):
        self.df = fixture_dataframe()
        self.dataset = DATASETS['4']
        self.documents = build_documents(self.df, self.dataset)

    def test_documentos_gerados_cobrem_os_quatro_tipos(self):
        kinds = {document.kind for document in self.documents}
        self.assertEqual(kinds, {OVERVIEW, COLUMN, AGGREGATE, ROWS})

    def test_visao_geral_traz_totais_e_metricas(self):
        overview = next(d for d in self.documents if d.kind == OVERVIEW)
        self.assertIn('linhas: 25', overview.text)
        self.assertIn('score_average_Mobat', overview.text)

    def test_documento_de_coluna_descreve_atributo(self):
        column_doc = next(d for d in self.documents if d.title.startswith('abuseipdb_country_code'))
        self.assertIn('país', column_doc.text)
        self.assertIn('BR', column_doc.text)

    def test_agregacao_por_pais_traduz_codigos_para_portugues(self):
        aggregate = next(
            d for d in self.documents
            if d.kind == AGGREGATE and 'país' in d.title.lower()
        )
        self.assertIn('BR (Brasil)', aggregate.text)
        self.assertIn('RU (Rússia)', aggregate.text)
        self.assertIn('score médio', aggregate.text)

    def test_linhas_serializadas_mantem_atributo_valor(self):
        rows_docs = [d for d in self.documents if d.kind == ROWS]
        self.assertTrue(rows_docs)
        self.assertIn('abuseipdb_country_code:', rows_docs[0].text)
        self.assertIn('score_average_Mobat:', rows_docs[0].text)

    def test_chunking_respeita_tamanho_minimo_e_over_lap(self):
        rows = [f'linha-{index} ' + 'x' * 40 for index in range(60)]
        chunks = _split_rows(rows, target=60, overlap=30, min_rows=3)

        self.assertGreater(len(chunks), 3)
        first, second = chunks[0][0], chunks[1][0]
        self.assertTrue(set(first) & set(second))
        for chunk, start, end in chunks:
            self.assertTrue(chunk)
            self.assertEqual(end - start + 1, len(chunk))

    def test_country_label(self):
        self.assertEqual(country_label('br'), 'BR (Brasil)')
        self.assertEqual(country_label('ZZ'), 'ZZ')
        self.assertEqual(country_label('desconhecido'), 'desconhecido')


class NumericCleanupTests(SimpleTestCase):
    def test_repara_valores_corrompidos_por_separador_de_milhar(self):
        from mobat_app.rag.numeric import to_numeric_clean

        series = pd.Series(['4.642.857.142.857.140', '45.857.142.857.142.800', '46.5', 55.0])
        cleaned = to_numeric_clean(series)

        self.assertAlmostEqual(cleaned.iloc[0], 46.43, places=1)
        self.assertAlmostEqual(cleaned.iloc[1], 45.86, places=1)
        self.assertAlmostEqual(cleaned.iloc[2], 46.5)
        self.assertAlmostEqual(cleaned.iloc[3], 55.0)
        self.assertTrue((cleaned.dropna().abs() < 500).all())

    def test_colunas_numericas_e_textuais(self):
        from mobat_app.rag.numeric import to_numeric_clean

        numerica = to_numeric_clean(pd.Series([1.0, 2.5, None]))
        self.assertEqual(list(numerica.dropna()), [1.0, 2.5])

        texto = to_numeric_clean(pd.Series(['BR', 'RU', 'n/a']))
        self.assertTrue(texto.isna().all())

    def test_describe_clean_conta_valores_reparados(self):
        from mobat_app.rag.numeric import describe_clean

        series = pd.Series(['4.642.857.142.857.140', '47.5', '47.5', '47.5'])
        cleaned, repaired = describe_clean(series)

        self.assertEqual(repaired, 1)
        self.assertTrue(cleaned.notna().all())

    def test_base_real_score_average_mobat_e_recuperavel(self):
        from mobat_app.rag.datasets import DATASETS, load_dataframe
        from mobat_app.rag.numeric import describe_clean

        dataset = DATASETS['4']
        if not dataset.sqlite_path.is_file():
            self.skipTest('base Total.sqlite indisponível')

        dataframe = load_dataframe(dataset)
        cleaned, repaired = describe_clean(dataframe['score_average_Mobat'])

        self.assertGreater(repaired, 1000, 'esperava-se corrupção na base Total')
        self.assertGreater(cleaned.notna().mean(), 0.95)
        self.assertLess(float(cleaned.max()), 500)

    def test_sandbox_expoe_clean_number(self):
        from mobat_app.rag.sandbox import run_pandas_code

        df = pd.DataFrame({
            'score_average_Mobat': ['4.642.857.142.857.140', '47.5', '47.5', '46.5'],
            'IP': ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4'],
        })
        result = run_pandas_code(
            "result = round(float(clean_number(df['score_average_Mobat']).mean()), 2)",
            df,
        )
        self.assertTrue(result.ok, result.error)
        self.assertAlmostEqual(float(result.output), 47.0, delta=1.5)


class VectorIndexTests(SimpleTestCase):
    def setUp(self):
        self.dataset = DATASETS['4']
        self.documents = build_documents(fixture_dataframe(), self.dataset)
        self.index = VectorIndex(self.documents)

    def test_busca_por_pais_em_portugues_encontra_agregacao(self):
        results = self.index.search('quantos IPs da Rússia', k=5, threshold=0.05)
        self.assertTrue(results)
        top_document, score = results[0]
        self.assertGreater(score, 0.1)
        self.assertTrue(
            top_document.kind in {AGGREGATE, COLUMN}
            or 'Rússia' in top_document.text
        )

    def test_busca_por_coluna_encontra_perfil(self):
        results = self.index.search('abuseipdb_country_code', k=3, threshold=0.01)
        titles = [document.title for document, _ in results]
        self.assertTrue(any('abuseipdb_country_code' in title for title in titles))

    def test_limiar_filtra_resultados_irrelevantes(self):
        results = self.index.search('pergunta sem sentido zebra xadrez', k=5, threshold=0.95)
        self.assertEqual(results, [])

    def test_busca_vazia_quando_query_vazia(self):
        self.assertEqual(self.index.search('   ', k=5, threshold=0.0), [])

    def test_nome_de_coluna_exato_vem_primeiro(self):
        results = self.index.search('o que significa a coluna abuseipdb_country_code', k=5, threshold=0.0)
        self.assertTrue(results)
        self.assertTrue(results[0][0].title.startswith('abuseipdb_country_code'))

    def test_titulo_do_documento_participa_da_busca(self):
        results = self.index.search('quais IPs foram mais denunciados', k=3, threshold=0.0)
        self.assertTrue(results)
        self.assertIn('mais denunciados', results[0][0].title)

    def test_pergunta_de_ruido_fica_abaixo_do_limiar(self):
        results = self.index.search('como fazer bolo de cenoura', k=3, threshold=0.0)
        self.assertTrue(results)
        self.assertLess(results[0][1], 0.15)

    def test_stopwords_em_portugues_nao_indexadas(self):
        vocabulary = self.index.word_vectorizer.vocabulary_
        self.assertNotIn('de', vocabulary)
        self.assertNotIn('do', vocabulary)
        self.assertIn('abuseipdb_country_code', vocabulary)


class SandboxTests(SimpleTestCase):
    def setUp(self):
        self.df = fixture_dataframe()

    def test_executa_agregacao_real(self):
        result = run_pandas_code(
            "result = int((df['abuseipdb_country_code'] == 'BR').sum())",
            self.df,
        )
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.output, '12')

    def test_groupby_e_value_counts(self):
        result = run_pandas_code(
            "result = df.groupby('abuseipdb_country_code')['score_average_Mobat'].mean()",
            self.df,
        )
        self.assertTrue(result.ok, result.error)
        self.assertIn('BR', result.output)

    def test_dataframes_de_grupo_preservam_o_indice(self):
        result = run_pandas_code(
            "result = df.groupby('abuseipdb_country_code')['score_average_Mobat']"
            ".agg(['mean', 'count']).sort_values('mean').head(1)",
            self.df,
        )
        self.assertTrue(result.ok, result.error)
        self.assertIn('US', result.output)
        self.assertIn('mean', result.output)

    def test_ultima_expressao_e_capturada(self):
        result = run_pandas_code('len(df)', self.df)
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.output, '25')

    def test_bloqueia_import(self):
        result = run_pandas_code('import os\nresult = 1', self.df)
        self.assertFalse(result.ok)
        self.assertIn('não permitida', result.error)

    def test_bloqueia_open_e_eval(self):
        for code in ("open('/etc/passwd')", "eval('1+1')", "exec('x=1')", "__import__('os')"):
            result = run_pandas_code(code, self.df)
            self.assertFalse(result.ok, code)

    def test_bloqueia_atributo_dunder(self):
        result = run_pandas_code('result = df.__class__', self.df)
        self.assertFalse(result.ok)
        self.assertIn('Atributo proibido', result.error)

    def test_bloqueia_escape_via_subclasse(self):
        result = run_pandas_code('result = ().__class__.__bases__', self.df)
        self.assertFalse(result.ok)

    def test_bloqueia_leitura_de_arquivo_pandas(self):
        result = run_pandas_code("result = pd.read_csv('/etc/passwd')", self.df)
        self.assertFalse(result.ok)

    def test_erro_de_execucao_e_reportado(self):
        result = run_pandas_code("result = df['coluna_inexistente']", self.df)
        self.assertFalse(result.ok)
        self.assertIn('KeyError', result.error)

    def test_timeout_em_loop_infinito(self):
        result = run_pandas_code('while True:\n    pass', self.df, timeout=1.0)
        self.assertFalse(result.ok)
        self.assertIn('tempo limite', result.error)

    def test_nao_altera_dataframe_original(self):
        run_pandas_code("df['novo'] = 1\nresult = 1", self.df)
        self.assertNotIn('novo', self.df.columns)

    def test_format_value_trunca_saida(self):
        from mobat_app.rag.sandbox import format_value

        text = format_value('x' * 9000, max_output=100)
        self.assertLessEqual(len(text), 140)
        self.assertIn('truncada', text)


def _fake_response(status_code=200, payload=None, text='', headers=None):
    response = mock.Mock()
    response.status_code = status_code
    response.text = text or json.dumps(payload or {})
    response.headers = headers or {}
    response.json.return_value = payload or {}
    return response


@override_settings(
    OLLAMA_MIN_REQUEST_INTERVAL=0,
    OLLAMA_RATE_LIMIT_BACKOFF_BASE=0,
    OLLAMA_RATE_LIMIT_MAX_BACKOFF=0,
    OLLAMA_MAX_RETRIES=2,
    OLLAMA_MAX_CONCURRENT_REQUESTS=2,
)
class OllamaClientTests(SimpleTestCase):
    def setUp(self):
        self.client = OllamaClient(
            host='https://ollama.test',
            api_keys=['chave-1', 'chave-2'],
            default_model='gemma4:cloud',
        )

    def test_sucesso_usa_primeira_chave_e_monta_payload(self):
        with mock.patch.object(self.client.session, 'post', return_value=_fake_response(
            200, {'message': {'role': 'assistant', 'content': 'ok'}, 'done': True}
        )) as post:
            data = self.client.chat([{'role': 'user', 'content': 'oi'}], temperature=0.1)

        self.assertEqual(data['message']['content'], 'ok')
        _, kwargs = post.call_args
        headers = kwargs['headers']
        self.assertEqual(headers['Authorization'], 'Bearer chave-1')
        payload = json.loads(kwargs['data'])
        self.assertEqual(payload['model'], 'gemma4:cloud')
        self.assertFalse(payload['stream'])
        self.assertEqual(payload['options']['temperature'], 0.1)

    def test_rotaciona_chave_apos_401(self):
        responses = [_fake_response(401, text='unauthorized'), _fake_response(
            200, {'message': {'role': 'assistant', 'content': 'ok'}}
        )]
        with mock.patch.object(self.client.session, 'post', side_effect=responses) as post:
            data = self.client.chat([{'role': 'user', 'content': 'oi'}])

        self.assertEqual(data['message']['content'], 'ok')
        self.assertEqual(post.call_count, 2)
        first_headers = post.call_args_list[0].kwargs['headers']
        second_headers = post.call_args_list[1].kwargs['headers']
        self.assertEqual(first_headers['Authorization'], 'Bearer chave-1')
        self.assertEqual(second_headers['Authorization'], 'Bearer chave-2')

    def test_erro_400_nao_tenta_novamente(self):
        with mock.patch.object(self.client.session, 'post', return_value=_fake_response(
            400, text='modelo inválido'
        )) as post:
            with self.assertRaises(OllamaError) as ctx:
                self.client.chat([{'role': 'user', 'content': 'oi'}])

        self.assertEqual(post.call_count, 1)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_rate_limit_esgota_tentativas(self):
        with mock.patch.object(self.client.session, 'post', return_value=_fake_response(
            429, text='too many'
        )) as post:
            with self.assertRaises(OllamaRateLimited):
                self.client.chat([{'role': 'user', 'content': 'oi'}])

        self.assertEqual(post.call_count, 3)

    def test_chat_text_levanta_erro_em_resposta_vazia(self):
        with mock.patch.object(self.client.session, 'post', return_value=_fake_response(
            200, {'message': {'role': 'assistant', 'content': ''}}
        )):
            with self.assertRaises(OllamaError):
                self.client.chat_text([{'role': 'user', 'content': 'oi'}])

    def test_sem_chaves_envia_sem_autorizacao(self):
        client = OllamaClient(host='https://ollama.test', api_keys=[], default_model='x')
        with mock.patch.object(client.session, 'post', return_value=_fake_response(
            200, {'message': {'role': 'assistant', 'content': 'ok'}}
        )) as post:
            client.chat([{'role': 'user', 'content': 'oi'}])

        self.assertNotIn('Authorization', post.call_args.kwargs['headers'])


@override_settings(CHATBOT_ENABLE_ANALYSIS=True, RAG_TFIDF_THRESHOLD=0.05)
class RagServiceTests(SimpleTestCase):
    def setUp(self):
        clear_cache()
        self.df = fixture_dataframe()
        self.dataset = DATASETS['4']
        self.index = VectorIndex(build_documents(self.df, self.dataset))

    def tearDown(self):
        clear_cache()

    def test_ask_combina_contexto_agregacao_e_resposta(self):
        fake = FakeOllamaClient()
        with mock.patch.object(service, 'get_index', return_value=self.index), \
                mock.patch.object(service, 'get_dataframe', return_value=self.df):
            answer = service.ask('Quantos IPs do Brasil?', self.dataset, client=fake)

        self.assertEqual(answer.answer, 'Resposta final.')
        self.assertEqual(answer.model, 'modelo-fake')
        self.assertTrue(answer.sources)

        self.assertTrue(answer.analysis.attempted)
        self.assertTrue(answer.analysis.ok, answer.analysis.error)
        self.assertEqual(answer.analysis.output, '12')

        final_call = fake.calls[-1]
        content = final_call['messages'][-1]['content']
        self.assertIn('CONTEXTO RECUPERADO', content)
        self.assertIn('AGREGAÇÕES EXECUTADAS', content)
        self.assertIn('Resultado calculado', content)
        self.assertIn('RESUMO ESTATÍSTICO', content)
        self.assertIn('Quantos IPs do Brasil?', content)

    def test_ask_mantem_historico_na_conversa(self):
        fake = FakeOllamaClient()
        history = [
            {'role': 'user', 'content': 'pergunta anterior'},
            {'role': 'assistant', 'content': 'resposta anterior'},
        ]
        with mock.patch.object(service, 'get_index', return_value=self.index), \
                mock.patch.object(service, 'get_dataframe', return_value=self.df):
            service.ask('E agora?', self.dataset, history=history, client=fake)

        roles = [message['role'] for message in fake.calls[-1]['messages']]
        self.assertEqual(roles, ['system', 'user', 'assistant', 'user'])

    def test_ask_com_analise_desativada(self):
        fake = FakeOllamaClient()
        with mock.patch.object(service, 'get_index', return_value=self.index), \
                mock.patch.object(service, 'get_dataframe', return_value=self.df):
            answer = service.ask(
                'Qual o período?', self.dataset, client=fake, enable_analysis=False
            )

        self.assertIsNone(answer.analysis)
        self.assertEqual(len(fake.calls), 1)

    def test_falha_do_llm_propaga_erro(self):
        class BrokenClient:
            default_model = 'quebrado'

            def chat_text(self, *args, **kwargs):
                raise OllamaError('sem chave')

        with mock.patch.object(service, 'get_index', return_value=self.index), \
                mock.patch.object(service, 'get_dataframe', return_value=self.df):
            with self.assertRaises(OllamaError):
                service.ask('algo', self.dataset, client=BrokenClient())

    def test_analyst_tenta_novamente_quando_codigo_falha(self):
        fake = FakeOllamaClient(code="result = df['coluna_que_nao_existe']")
        result = analyse('pergunta', self.df, self.dataset, client=fake)
        self.assertFalse(result.ok)
        self.assertEqual(result.rounds, 2)

        second_call = fake.calls[-1]
        self.assertTrue(
            any('falhou com o erro' in message['content'] for message in second_call['messages']),
            'a nova tentativa não recebeu o erro do código anterior',
        )

    def test_dataframe_schema_lista_colunas(self):
        schema = dataframe_schema(self.df)
        self.assertIn('score_average_Mobat', schema)
        self.assertIn('abuseipdb_country_code', schema)

    def test_dataset_from_session(self):
        session = {'table_choice': '2'}
        self.assertEqual(dataset_from_session(session).key, '2')
        self.assertEqual(dataset_from_session({}).key, '4')
        session = {'table_choice': '99', 'db_path': 'mobat_app/Seasons/TerceiroSemestre.sqlite'}
        self.assertEqual(dataset_from_session(session).key, '3')


class ChatbotViewTests(TestCase):
    def setUp(self):
        clear_cache()

    def tearDown(self):
        clear_cache()

    def test_status_retorna_json_e_dispara_aquecimento(self):
        with mock.patch('mobat_app.rag.index.warmup') as warmup:
            response = self.client.get(reverse('chatbot_status'))

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data['enabled'])
        self.assertEqual(data['dataset'], 'Total-Coletado')
        self.assertIn('model', data)
        warmup.assert_called_once()

    def test_ask_valida_pergunta_vazia(self):
        response = self.client.post(
            reverse('chatbot_ask'), data=json.dumps({}), content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn('pergunta', response.json()['error'].lower())

    def test_ask_valida_tamanho_maximo(self):
        response = self.client.post(
            reverse('chatbot_ask'),
            data=json.dumps({'question': 'x' * 5000}),
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 400)

    def test_ask_devolve_resposta_com_fontes(self):
        answer = service.ChatAnswer(
            question='quantos?',
            answer='São 12 IPs.',
            dataset='Total-Coletado',
            model='gemma4:cloud',
            sources=[service.Source(AGGREGATE, 'Agregação estatística', 'país – Total', 0.4)],
            analysis=None,
            elapsed=1.5,
        )
        with mock.patch.object(service, 'ask', return_value=answer) as ask:
            response = self.client.post(
                reverse('chatbot_ask'),
                data=json.dumps({'question': 'quantos?', 'history': []}),
                content_type='application/json',
            )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['answer'], 'São 12 IPs.')
        self.assertEqual(data['sources'][0]['kind'], AGGREGATE)
        ask.assert_called_once()
        self.assertEqual(ask.call_args.args[0], 'quantos?')

    def test_ask_erro_do_llm_vira_502(self):
        with mock.patch.object(service, 'ask', side_effect=OllamaError('sem chave')):
            response = self.client.post(
                reverse('chatbot_ask'),
                data=json.dumps({'question': 'algo'}),
                content_type='application/json',
            )

        self.assertEqual(response.status_code, 502)
        self.assertIn('modelo', response.json()['error'].lower())

    def test_ask_respeita_dataset_escolhido(self):
        answer = service.ChatAnswer(
            question='x', answer='y', dataset='Abril-Maio(2023)', model='m'
        )
        with mock.patch.object(service, 'ask', return_value=answer) as ask:
            self.client.post(
                reverse('chatbot_ask'),
                data=json.dumps({'question': 'x', 'dataset_key': '1'}),
                content_type='application/json',
            )

        self.assertEqual(ask.call_args.args[1].key, '1')

    def test_metodo_nao_permitido(self):
        response = self.client.get(reverse('chatbot_ask'))
        self.assertEqual(response.status_code, 405)


class ChatbotWidgetMiddlewareTests(TestCase):
    def test_widget_e_injetado_na_pagina_inicial(self):
        response = self.client.get(reverse('index'))

        self.assertEqual(response.status_code, 200)
        content = response.content.decode()
        self.assertIn('mobat-chatbot-root', content)
        self.assertIn(reverse('chatbot_ask'), content)
        self.assertIn('Assistente de dados', content)
        self.assertLess(content.index('mobat-chatbot-root'), content.index('</body>'))

    def test_widget_e_injetado_nas_paginas_de_funcionalidade(self):
        self.client.get(reverse('visualizar_funcionalidades'), {'table_choice': '4'})
        response = self.client.get(reverse('visualizar_funcionalidades'), {'table_choice': '4'})

        self.assertIn('mobat-chatbot-root', response.content.decode())

    def test_nao_injeta_em_respostas_json(self):
        response = self.client.get(reverse('chatbot_status'))

        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertNotIn('mobat-chatbot-root', response.content.decode())

    def test_nao_injeta_em_status_diferente_de_200(self):
        response = self.client.get('/rota-que-nao-existe/')

        self.assertEqual(response.status_code, 404)
        self.assertNotIn('mobat-chatbot-root', response.content.decode())

    def test_nao_injeta_em_requisicoes_post(self):
        response = self.client.post(reverse('index'), {})

        self.assertNotIn('mobat-chatbot-root', response.content.decode())

    def test_nao_duplica_o_widget(self):
        first = self.client.get(reverse('index')).content.decode()
        self.assertEqual(first.count('<div id="mobat-chatbot-root"'), 1)
        self.assertEqual(first.count('id="mobat-chatbot-styles"'), 1)

    def test_injetado_apenas_uma_vez_mesmo_com_dois_middlewares(self):
        content = self.client.get(reverse('index')).content.decode()
        self.assertEqual(content.count('id="mobat-chatbot-root"'), 1)

    def test_desativado_via_settings(self):
        with override_settings(CHATBOT_ENABLED=False):
            response = self.client.get(reverse('index'))

        self.assertNotIn('mobat-chatbot-root', response.content.decode())

    def test_conteudo_da_config_e_json_valido(self):
        content = self.client.get(reverse('index')).content.decode()
        start = content.index('<script id="mobat-chatbot-config" type="application/json">')
        begin = content.index('>', start) + 1
        end = content.index('</script>', begin)
        config = json.loads(content[begin:end])

        self.assertEqual(config['datasetKey'], '4')
        self.assertEqual(config['askUrl'], reverse('chatbot_ask'))
        self.assertTrue(config['csrfToken'])

    def test_css_do_painel_so_exibe_quando_aberto(self):
        content = self.client.get(reverse('index')).content.decode()
        css = content[content.index('<style id="mobat-chatbot-styles">'):]

        base_rule = re.search(r'#mobat-chatbot-root \.mc-panel \{(.*?)\}', css, re.S).group(1)
        displays = re.findall(r'display\s*:\s*([^;]+);', base_rule)
        self.assertTrue(displays, 'regra base do painel precisa declarar display')
        self.assertEqual(displays[-1].strip(), 'none')

        open_rule = re.search(r'#mobat-chatbot-root\[data-open="true"\] \.mc-panel \{[^}]*\}', css).group(0)
        self.assertIn('display: flex', open_rule)


class StatisticalSummaryTests(SimpleTestCase):
    def setUp(self):
        clear_stats_cache()
        self.df = fixture_dataframe()

    def tearDown(self):
        clear_stats_cache()

    def test_resumo_traz_medidas_descritivas(self):
        block = statistical_summary(self.df, use_cache=False)

        self.assertIn('RESUMO ESTATÍSTICO', block)
        self.assertIn('score_average_Mobat', block)
        self.assertIn('mediana=', block)
        self.assertIn('desvio=', block)
        self.assertIn('outliers IQR=', block)

    def test_correlacoes_com_a_metrica_principal(self):
        block = statistical_summary(self.df, use_cache=False)

        self.assertIn('Correlação com score_average_Mobat', block)
        self.assertIn('Spearman', block)
        self.assertIn('Pearson', block)
        self.assertIn('abuseipdb_total_reports', block)
        self.assertIn('não implica causalidade', block)

    def test_cache_reusa_o_mesmo_bloco(self):
        first = statistical_summary(self.df)
        second = statistical_summary(self.df)

        self.assertEqual(first, second)

    def test_base_sem_colunas_numericas_nao_quebra(self):
        block = statistical_summary(pd.DataFrame({'letra': ['a', 'b', 'c']}), use_cache=False)

        self.assertIn('RESUMO ESTATÍSTICO', block)


class RagEvaluationTests(SimpleTestCase):
    def setUp(self):
        self.index = VectorIndex(build_documents(fixture_dataframe(), DATASETS['4']))
        self.report = evaluate_index(self.index, k=5, threshold=0.15)

    def test_relatorio_inclui_todas_as_metricas(self):
        metrics = self.report['metrics']

        for key in (
            'hit_rate_at_k', 'hit_rate_at_production_k', 'precision_at_k', 'mean_reciprocal_rank',
            'recall_at_threshold', 'recall_with_fallback', 'false_positive_rate_at_threshold',
            'auc', 'mann_whitney_u', 'p_value', 'recommended_threshold', 'verdict',
        ):
            self.assertIn(key, metrics)

        for key in ('hit_rate_at_k', 'auc', 'false_positive_rate_at_threshold', 'recall_with_fallback'):
            self.assertGreaterEqual(metrics[key], 0.0, key)
            self.assertLessEqual(metrics[key], 1.0, key)

    def test_sinal_separa_do_ruido_estatisticamente(self):
        metrics = self.report['metrics']

        self.assertGreaterEqual(metrics['auc'], 0.9)
        self.assertLess(metrics['p_value'], 0.05)
        self.assertEqual(metrics['false_positive_rate_at_threshold'], 0.0)
        self.assertEqual(metrics['verdict'], 'BOM')

        noise = [item['top_score'] for item in self.report['negatives']]
        self.assertTrue(all(score < 0.15 for score in noise))

    def test_perguntas_recebem_o_documento_esperado(self):
        metrics = self.report['metrics']

        self.assertGreaterEqual(metrics['hit_rate_at_k'], 0.8)
        self.assertEqual(metrics['recall_with_fallback'], 1.0)
        for item in self.report['positives']:
            self.assertIsNotNone(item['rank'], item['query'])

    def test_format_report_mostra_verdicto_e_metricas(self):
        text = format_report(self.report)

        self.assertIn('VERDICTO: BOM', text)
        self.assertIn('Mann-Whitney', text)
        self.assertIn('falsos positivos', text)

    def test_comando_evaluate_rag_roda_sobre_o_indice(self):
        from mobat_app.management.commands import evaluate_rag as evaluate_module

        with mock.patch.object(evaluate_module, 'get_index', return_value=self.index):
            out = StringIO()
            call_command('evaluate_rag', '--dataset', '4', stdout=out)

        self.assertIn('VERDICTO', out.getvalue())

    def test_comando_rejeita_dataset_desconhecido(self):
        from django.core.management.base import CommandError

        from mobat_app.management.commands import evaluate_rag as evaluate_module

        with mock.patch.object(evaluate_module, 'get_index', return_value=self.index):
            with self.assertRaises(CommandError):
                call_command('evaluate_rag', '--dataset', '99', stdout=StringIO())


class FeatureImportanceTests(SimpleTestCase):
    allowed_columns = [
        'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_total_reports',
        'abuseipdb_num_distinct_users', 'virustotal_reputation', 'harmless', 'malicious',
        'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score',
        'IBM_most common score', 'score_average_Mobat',
    ]
    modelos = (
        'GradientBoostingRegressor', 'RandomForestRegressor', 'ExtraTreesRegressor',
        'AdaBoostRegressor', 'XGBRegressor', 'ElasticNet',
    )

    def _dataframe(self, rows=60, alvo=None):
        base = pd.DataFrame({
            'abuseipdb_is_whitelisted': ['TRUE' if i % 3 else 'FALSE' for i in range(rows)],
            'abuseipdb_confidence_score': [float((i * 13) % 100) for i in range(rows)],
            'abuseipdb_total_reports': [float(i % 40) for i in range(rows)],
            'abuseipdb_num_distinct_users': [float(i % 25) for i in range(rows)],
            'virustotal_reputation': [float((i * 7) % 60) for i in range(rows)],
            'harmless': [float(i % 70) for i in range(rows)],
            'malicious': [float(i % 5) for i in range(rows)],
            'suspicious': [float(i % 9) for i in range(rows)],
            'undetected': [float(i % 60) for i in range(rows)],
            'IBM_score': [float((i * 11) % 100) for i in range(rows)],
            'IBM_average history Score': [float((i * 3) % 100) for i in range(rows)],
            'IBM_most common score': [float((i * 5) % 100) for i in range(rows)],
        })
        base['score_average_Mobat'] = (
            alvo if alvo is not None else [30.0 + (i % 20) for i in range(rows)]
        )
        return base

    def test_todos_os_modelos_geram_grafico_png(self):
        df = self._dataframe()

        for model_type in self.modelos:
            with self.subTest(model_type=model_type):
                graphic = plot_feature_importance(df, self.allowed_columns, model_type)

                self.assertTrue(base64.b64decode(graphic).startswith(b'\x89PNG'))

    def test_modelo_desconhecido_dispara_value_error(self):
        with self.assertRaises(ValueError):
            plot_feature_importance(self._dataframe(), self.allowed_columns, 'ModeloInexistente')

    def test_alvo_corrompido_e_reparado_como_numero(self):
        df = self._dataframe(alvo=['4.842.857.142.857.140'] * 30 + ['4.657.142.857.142.850'] * 30)

        limpo = categorize_non_numeric_columns(df)

        self.assertTrue(pd.api.types.is_float_dtype(limpo['score_average_Mobat']))
        self.assertTrue(limpo['score_average_Mobat'].between(1.0, 500.0).all())
        self.assertFalse(limpo['score_average_Mobat'].isin([0, 1, 2, 3, 4, 5]).all())

    def test_coluna_nao_numerica_continua_como_codigo_de_categoria(self):
        limpo = categorize_non_numeric_columns(self._dataframe())

        self.assertTrue(pd.api.types.is_integer_dtype(limpo['abuseipdb_is_whitelisted']))
        self.assertLessEqual(limpo['abuseipdb_is_whitelisted'].max(), 1)

    def test_valores_ausentes_nao_quebram_o_ajuste(self):
        df = self._dataframe(alvo=['46.5', ''] * 30)

        graphic = plot_feature_importance(df, self.allowed_columns, 'ElasticNet')

        self.assertTrue(base64.b64decode(graphic).startswith(b'\x89PNG'))


class ImportanciaMlViewTests(TestCase):
    colunas = [
        'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
        'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
        'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
        'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
        'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn',
        'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat',
    ]
    texto = {
        'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_country_code', 'abuseipdb_isp',
        'abuseipdb_domain', 'abuseipdb_last_reported_at', 'virustotal_regional_internet_registry',
        'virustotal_as_owner', 'SHODAN_isp', 'score_average_Mobat',
    }
    modelos = (
        'GradientBoostingRegressor', 'RandomForestRegressor', 'ExtraTreesRegressor',
        'AdaBoostRegressor', 'XGBRegressor', 'ElasticNet',
    )

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db_path = Path(tmp.name) / 'dados.sqlite'

        definicao = ', '.join(
            f'"{coluna}" {"TEXT" if coluna in self.texto else "REAL"}' for coluna in self.colunas
        )
        conn = sqlite3.connect(self.db_path)
        conn.execute(f'CREATE TABLE TotalTeste ({definicao})')
        linhas = []
        for i in range(60):
            linha = []
            for coluna in self.colunas:
                if coluna == 'IP':
                    linha.append(f'10.0.0.{i}')
                elif coluna == 'abuseipdb_is_whitelisted':
                    linha.append('TRUE' if i % 3 else 'FALSE')
                elif coluna == 'abuseipdb_country_code':
                    linha.append(['BR', 'CN', 'US'][i % 3])
                elif coluna in {'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_last_reported_at',
                                'virustotal_regional_internet_registry', 'virustotal_as_owner',
                                'SHODAN_isp'}:
                    linha.append('valor')
                elif coluna == 'score_average_Mobat':
                    linha.append('4.842.857.142.857.140')
                else:
                    linha.append(float((i * 7) % 100))
            linhas.append(tuple(linha))
        conn.executemany(
            f"INSERT INTO TotalTeste VALUES ({','.join('?' * len(self.colunas))})", linhas
        )
        conn.commit()
        conn.close()

        session = self.client.session
        session['db_path'] = str(self.db_path)
        session['table_name'] = 'TotalTeste'
        session.save()

    def test_pagina_renderiza_o_formulario(self):
        response = self.client.get(reverse('importancias_ml'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Importâncias para Machine Learning')

    def test_todos_os_modelos_do_formulario_retornam_grafico(self):
        for model_type in self.modelos:
            with self.subTest(model_type=model_type):
                response = self.client.post(reverse('importancias_ml'), {
                    'action': 'Visualizar Gráfico de Importância',
                    'model_type': model_type,
                })

                self.assertEqual(response.status_code, 200)
                self.assertContains(response, 'data:image/png;base64,')
                self.assertTrue(self.client.session.get('graphic'))

    def test_sem_banco_na_sessao_retorna_400(self):
        session = self.client.session
        session.pop('db_path', None)
        session.save()

        response = self.client.post(reverse('importancias_ml'), {
            'action': 'Visualizar Gráfico de Importância',
            'model_type': 'RandomForestRegressor',
        })

        self.assertEqual(response.status_code, 400)

    def test_baixar_grafico_devolve_png_e_limpa_a_sessao(self):
        session = self.client.session
        session['graphic'] = base64.b64encode(b'\x89PNG\r\n\x1a\nconteudo').decode()
        session.save()

        response = self.client.post(reverse('importancias_ml'), {
            'action': 'Baixar Gráfico',
            'model_type': 'ElasticNet',
        })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'image/png')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertTrue(response.content.startswith(b'\x89PNG'))
        self.assertFalse(self.client.session.get('graphic'))
