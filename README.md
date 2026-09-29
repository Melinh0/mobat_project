# mobat_project

Ips data analysis tool applied in a web environment using the Django framework.
A ferramenta também traz um **assistente de dados com RAG** (chatbot por widget
flutuante) que responde perguntas sobre as bases de IPs coletadas
(Seasons/Sheets) usando busca vetorial, agregações reais em pandas e um resumo
estatístico da base inteira.

**Sumário**

1. [Requisitos](#1-requisitos)
2. [Configuração (`.env`)](#2-configuração-env)
3. [Execução passo a passo](#3-execução-passo-a-passo)
4. [Como usar o chatbot](#4-como-usar-o-chatbot)
5. [Como funciona (arquitetura)](#5-como-funciona-arquitetura)
6. [Comandos úteis](#6-comandos-úteis)
7. [Resultados da execução de hoje](#7-resultados-da-execução-de-hoje)
8. [Estrutura do projeto](#8-estrutura-do-projeto)
9. [Observações sobre os dados](#9-observações-sobre-os-dados)

---

## 1. Requisitos

| Item | Detalhe |
|------|---------|
| Python | `>= 3.12` (declarado no `pyproject.toml`) |
| Gerenciador | [`uv`](https://docs.astral.sh/uv/) **ou** `pip` |
| Banco | SQLite (`db.sqlite3`, criado automaticamente) |
| LLM | Chave(s) de API do **Ollama cloud** (`https://ollama.com`) |
| Python packages | Django 4.2, DRF, pandas, scikit-learn, numpy, matplotlib, geopandas, pycountry, xgboost, drf-yasg (ver `pyproject.toml`) |

## 2. Configuração (`.env`)

Crie seu arquivo de ambiente a partir do exemplo:

```bash
cp .env.example .env
```

Edite pelo menos dois campos do `.env`:

* `OLLAMA_API_KEY` – suas chaves, **separadas por vírgula** (o cliente rotaciona
  entre elas quando uma atinge limite/429);
* `SECRET_KEY` – segredo do Django.

O loader é `mobat_project/env.py`: lê o `.env` da raiz, **não sobrescreve**
variáveis que já existem no ambiente do processo (padrão Docker/CI) e expõe
`env_str/env_int/env_float/env_bool/env_list` usados pelos settings.

### Variáveis

| Variável | Padrão | Descrição |
|----------|--------|-----------|
| `SECRET_KEY` | – | segredo do Django |
| `DJANGO_DEBUG` | `1` | modo debug do Django |
| `OLLAMA_HOST` | `https://ollama.com` | endpoint da API |
| `OLLAMA_API_KEY` | – | chaves separadas por vírgula (rotação) |
| `OLLAMA_AVAILABLE_MODELS` | `gemma4:cloud, …` | modelos disponíveis |
| `OLLAMA_VISION_MODELS` | `gemma4:cloud` | modelos com visão |
| `DEFAULT_MODEL` | `gemma4:cloud` | modelo padrão das respostas |
| `OLLAMA_MAX_TOKENS` | 16000 | limite de tokens da geração |
| `OLLAMA_REQUEST_TIMEOUT` | 600 | timeout total da requisição (s) |
| `OLLAMA_CONNECT_TIMEOUT` | 15 | timeout de conexão (s) |
| `OLLAMA_MAX_RETRIES` | 3 | tentativas por requisição |
| `OLLAMA_MAX_CONCURRENT_REQUESTS` | 4 | semáforo de concorrência |
| `OLLAMA_MIN_REQUEST_INTERVAL` | 0.5 | intervalo mínimo entre chamadas (s) |
| `OLLAMA_RATE_LIMIT_BACKOFF_BASE` / `…_MAX_BACKOFF` | 5 / 120 | backoff exponencial em 429/5xx |
| `ANALYZE_TEMPERATURE_WITH_RAG` / `…_WITHOUT_RAG` | 0.3 / 0.0 | temperatura da resposta com/sem contexto |
| `GEN_TEMPERATURE_GENERIC` | 0.0 | temperatura das chamadas genéricas |
| `RAG_TFIDF_THRESHOLD` | 0.15 | limiar do índice TF-IDF local |
| `RAG_SIMILARITY_THRESHOLD` | 0.72 | compatibilidade com o `.env` original (embeddings) |
| `RAG_N_RESULTS` | 12 | documentos enviados ao modelo |
| `RAG_WORD_MIN_DF` / `RAG_CHAR_MIN_DF` | 0 (automático: 1 / 3) | frequência mínima de documentos no TF-IDF |
| `INDEX_CHUNK_TARGET_SIZE` / `INDEX_CHUNK_OVERLAP` | 500 / 80 | granularidade dos blocos de linhas |
| `INDEX_MIN_ROWS_PER_CHUNK` | 10 | mínimo de linhas por documento de linhas |
| `CHATBOT_ENABLED` / `CHATBOT_ENABLE_ANALYSIS` | 1 / 1 | liga o widget e a etapa de agregação |
| `CHATBOT_HISTORY_LIMIT` / `CHATBOT_MAX_QUESTION_LENGTH` | 8 / 2000 | histórico e tamanho da pergunta |
| `CHATBOT_ANALYSIS_TIMEOUT` | 10 | limite do código pandas (s) |
| `RAG_SERVICE_URL` | `http://llm_api:8001` | compatibilidade (o RAG roda dentro do Django) |

## 3. Execução passo a passo

```bash
# 1) dependências
uv sync                      # ou: python -m venv .venv && source .venv/bin/activate && pip install -e .

# 2) variáveis de ambiente
cp .env.example .env         # preencha OLLAMA_API_KEY e SECRET_KEY

# 3) banco de dados (SQLite)
python manage.py migrate

# 4) servidor de desenvolvimento
python manage.py runserver 0.0.0.0:8010
# com uv: uv run python manage.py runserver 0.0.0.0:8010
```

Abra **http://localhost:8010/** – a aplicação lista as bases coletadas e o
chatbot aparece no canto inferior direito de todas as páginas.

Opcionalmente, aqueça o índice antes do primeiro uso (evita ~11 s na primeira
pergunta; o índice também é montado em background pela chamada
`/chatbot/status/`):

```bash
python manage.py warm_rag_index --dataset 4
# Indexando Total-Coletado – tabela Total ...
#   OK: 2497 documentos
```

### Com Docker

```bash
docker compose up --build     # sobe em http://localhost:8000
```

## 4. Como usar o chatbot

1. Escolha o período/base na interface (o widget acompanha a sessão; também dá
   para forçar com `dataset_key` no payload).
2. Clique no botão flutuante e pergunte em linguagem natural.
3. Aguarde a resposta (~14–18 s: recuperação + agregação pandas + geração).

Perguntas que funcionam bem:

* `quantos IPs existem na base`
* `qual país tem mais IPs`
* `qual o isp com mais endereços IP`
* `quais foram os IPs mais denunciados`
* `qual a média do score_average_Mobat`
* `o que significa a coluna abuseipdb_country_code`
* `como o Brasil se compara aos demais países`

Endpoints usados pelo widget:

| Rota | Descrição |
|------|-----------|
| `GET /chatbot/status/` | estado do índice/modelo (dispara indexação em background) |
| `POST /chatbot/ask/` | `{question, dataset_key, history}` → resposta, fontes e análise |

## 5. Como funciona (arquitetura)

1. **Corpus tabular** (`mobat_app/rag/corpus.py`) – cada período vira documentos
   de 4 tipos: visão geral, perfil de coluna, agregações (país/ISP/ASN/faixas de
   score) e blocos de linhas serializadas como `atributo: valor`.
2. **Índice vetorial** (`mobat_app/rag/index.py`) – TF-IDF local (palavras +
   caracteres, similaridade de cosseno) com scikit-learn. A API de embeddings do
   Ollama cloud está indisponível para as chaves atuais (`/api/embed` →
   `unauthorized`), por isso a vetorização é feita em memória no próprio Django.
   Índice em cache por período (~11 s e 2.497 documentos para a base Total).
3. **Agregações via pandas** (`mobat_app/rag/analyst.py` + `sandbox.py`) – o
   modelo devolve JSON com código pandas que é **validado (AST) e executado em
   namespace restrito** (sem `import`/`open`/atributos dunder, cópia do
   DataFrame, limite de tempo e de saída). O número exato entra na resposta.
4. **Resumo estatístico** (`mobat_app/rag/stats.py`) – sobre a base inteira,
   pandas/numpy calculam média, desvio, quartis, P90, assimetria, outliers pela
   regra do IQR e as correlações de Pearson/Spearman com `score_average_Mobat`.
   O bloco `RESUMO ESTATÍSTICO` entra no prompt como autoridade numérica.
5. **Geração** (`mobat_app/rag/service.py`) – contexto recuperado
   (limiar `RAG_TFIDF_THRESHOLD`) + agregações + resumo estatístico + histórico →
   `POST /api/chat` do Ollama com rotação de chaves, retries/backoff, semáforo
   de concorrência e intervalo mínimo entre requisições
   (`mobat_app/utils/ollama_client.py`).
6. **Widget** (`mobat_app/middleware.py` + `templates/chatbot/widget.html`) –
   injetado antes de `</body>` em toda resposta `text/html` 200, sem duplicar
   código nos templates.

## 6. Comandos úteis

```bash
# servidor
python manage.py runserver 0.0.0.0:8010

# indexa um período (1-4; 4 = Total)
python manage.py warm_rag_index --dataset 4

# avalia a qualidade da recuperação (hit@k, MRR, AUC, Mann-Whitney, veredito)
python manage.py evaluate_rag --dataset 4
python manage.py evaluate_rag --dataset 4 --json --fail-under 0.9

# suíte de testes (85 testes: RAG, estatísticas, avaliação, sandbox, views, widget, ML)
python manage.py test

# checagem estática do Django
python manage.py check
```

## 7. Resultados da execução de hoje

Tudo abaixo foi executado em **29/09/2026**, com o código atual
(`evaluate_rag`, `test`, `check` e respostas ao vivo na base **Total** –
22.173 linhas, 25 colunas, índice com 2.497 documentos, limiar 0,15).

### 7.1 Avaliação do RAG (`evaluate_rag --dataset 4`)

A ferramenta roda **11 perguntas típicas** (cada uma com o id do documento que
deveria ser recuperado) e **10 perguntas de ruído** como grupo de controle, e
calcula métricas de IR (hit@k, precision@k, MRR), medidas descritivas das
similaridades, AUC par a par e o teste de Mann-Whitney U.

| Métrica | Valor |
|---------|-------|
| hit@5 | **0,91** (10 de 11 no top-5) |
| hit@12 (profundidade real) | **1,00** (11 de 11) |
| precision@5 | 0,200 |
| MRR@5 / MRR@12 | 0,780 / 0,795 |
| recall no limiar 0,15 | 0,73 |
| recall no fluxo do serviço (com degradação) | **1,00** |
| falsos positivos no limiar | **0,00** (10 de 10 ruído abaixo do limiar) |
| similaridade top-1 – perguntas | média 0,221 · desvio 0,074 · mediana 0,250 · P10 0,133 · P90 0,302 |
| similaridade top-1 – ruído | média 0,083 · desvio 0,025 · mediana 0,075 · P10 0,058 · P90 0,124 |
| AUC (sinal × ruído) | **0,964** – Mann-Whitney U = 106, p = 1,88e-04 |
| limiar sugerido (Youden) | 0,133 |
| **veredito** | **BOM** |

Os 10 exemplos de ruído ("como fazer bolo de cenoura", "previsão do tempo em
Tóquio", …) ficaram todos entre 0,056 e 0,125 – abaixo do limiar de 0,15.

Com `--json --fail-under 0.9` o comando vira um teste de regressão utilizável
em CI.

### 7.2 Avaliações que mudaram o código

* `token_pattern` **sem `:`** – a serialização `coluna: valor` gerava tokens como
  `abuseipdb_country_code:` e a pergunta `abuseipdb_country_code` não casava em
  nível de palavra;
* **stopwords em português removidas** – `de`, `do` e `a` dominavam a similaridade
  do ruído (AUC 0,75 → 1,00; falsos positivos 60% → 0%);
* **título do documento indexado 3×** + bônus de `+0,15` para identificador exato
  citado na pergunta – hit@5 0,38 → 0,91;
* `RAG_WORD_MIN_DF=1` – `min_df=2` descartava âncoras raras de um único documento
  (ex.: `denunciados`, `quantos`).

### 7.3 Exemplos de respostas (ao vivo, base Total)

**1) `Qual país tem mais IPs e como o Brasil se compara a ele?`** (16,7 s)

> No período analisado (Total-Coletado), o país com o maior número de IPs é a
> China (CN), com 2.906 registros.
>
> Em comparação, o Brasil (BR) possui 437 IPs, o que representa uma quantidade
> significativamente menor que a da China.

Código pandas executado no sandbox: `value_counts()` em
`abuseipdb_country_code` → saída `CN 2906` / `BR 437`. Fontes citadas: visão
geral do período + agregação por país.

**2) `Qual é a média e o desvio padrão do score_average_Mobat e qual país tem a
pior média?`** (16,4 s)

> * **Média do `score_average_Mobat`**: 53,46
> * **Desvio Padrão do `score_average_Mobat`**: 7,38
> * **País com a pior média**: CH (Suíça), com média de 64,92.
>
> **Observação importante:** A média do país CH (Suíça) foi calculada com base em
> apenas 7 IPs (n = 7), o que representa uma amostra pequena e deve ser
> interpretada com cautela.

O sandbox devolveu `mean 53.46 / std 7.38` e o grupo `CH` com `count = 7`; a
regra "cite `n` e trate amostra pequena com cautela" está no SYSTEM_PROMPT.

**3) `O que significa a coluna abuseipdb_country_code?`**

> A coluna `abuseipdb_country_code` representa o código do país (no padrão ISO
> alpha-2) associado ao endereço IP, conforme identificado pelo serviço
> AbuseIPDB.
>
> No período analisado (Total-Coletado), a coluna está 100% preenchida (22.173
> registros), sendo os países com maior frequência de IPs a China (CN) com 2.906
> registros e os Estados Unidos (US) com 2.676 registros.

### 7.4 Suíte de testes

```text
$ python manage.py test
Ran 85 tests in 20.643s
OK

$ python manage.py check
System check identified no issues (0 silenced).
```

Cobertura: loader do `.env`, cliente Ollama (rotação/limites), corpus/índice/
recuperação, sandbox pandas (AST, limites, `clean_number`), resumo estatístico,
avaliação do RAG, endpoints do chatbot, injeção do widget via middleware, CSS do
painel (abrir/fechar/reabrir) e as **importâncias de ML** (os 6 modelos do
formulário, alvo corrompido reparado e download do PNG).

## 8. Estrutura do projeto

```text
mobat_project/
├── .env                      # credenciais/parâmetros (não versionado)
├── .env.example              # modelo do .env (sem segredos)
├── manage.py
├── mobat_project/
│   ├── env.py                # loader do .env + helpers env_*
│   ├── settings.py           # config do Django, Ollama e RAG
│   └── urls.py
└── mobat_app/
    ├── views.py              # telas da ferramenta (bases, gráficos, ML)
    ├── views/chatbot.py      # /chatbot/status/ e /chatbot/ask/
    ├── middleware.py         # injeta o widget antes de </body>
    ├── templates/chatbot/widget.html
    ├── utils/ollama_client.py
    ├── management/commands/
    │   ├── warm_rag_index.py
    │   └── evaluate_rag.py
    ├── rag/
    │   ├── datasets.py       # bases 1-4 (Seasons/Sheets) e leitura do SQLite
    │   ├── corpus.py         # documentos tabulares
    │   ├── index.py          # TF-IDF (palavras + n-grams de caractere)
    │   ├── numeric.py        # reparo de score_average_Mobat e sanitização
    │   ├── analyst.py        # geração do código de agregação
    │   ├── sandbox.py        # validação AST + execução limitada
    │   ├── stats.py          # resumo estatístico (autoridade numérica)
    │   ├── service.py        # recuperação + prompt + geração
    │   └── evaluation.py     # bateria de perguntas e métricas
    └── tests.py              # 85 testes
```

## 9. Observações sobre os dados

* `score_average_Mobat` está **corrompido em `SegundoSemestre` e `Total`**
  (ex.: `4.642.857.142.857.140` = `46.42857142857140` com separador de milhar
  por cima do decimal). `mobat_app/rag/numeric.py` detecta o padrão e reconstrói
  os valores na grandeza dos dados legíveis; os agregados do RAG já saem
  reparados e o sandbox expõe `clean_number()` para o modelo.
* As colunas `harmless`, `malicious`, `suspicious` e `undetected` do VirusTotal
  são escala **0–100** (não contagens de motores).
* Códigos de país são siglas ISO alpha-2 (`CH` = Suíça, `CN` = China,
  `CO` = Colômbia, `CA` = Canadá).
