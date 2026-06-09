import base64
import os
import re

import requests

BASE_URL = "http://127.0.0.1:8000"
IMAGES_DIR = "images"

os.makedirs(IMAGES_DIR, exist_ok=True)

session = requests.Session()


def get_csrf_token():
    resp = session.get(f"{BASE_URL}/visualizar_funcionalidades/?table_choice=1")
    csrf_token = session.cookies.get("csrftoken")
    if csrf_token:
        return csrf_token

    match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', resp.text)
    if match:
        return match.group(1)
    return None


def select_semester(table_choice="1"):
    resp = session.get(
        f"{BASE_URL}/visualizar_funcionalidades/", params={"table_choice": table_choice}
    )
    return resp.status_code == 200


def get_first_ip():
    select_semester("1")
    resp = session.get(f"{BASE_URL}/graficos_comportamento/")
    if resp.status_code != 200:
        return None

    match = re.search(r'<option value="([\d\.]+)"', resp.text)
    if match:
        return match.group(1)
    return None


def save_binary_response(response, filename):
    with open(os.path.join(IMAGES_DIR, filename), "wb") as file_obj:
        file_obj.write(response.content)


def save_image_from_datauri(data_uri, filename):
    if data_uri.startswith("data:image/png;base64,"):
        data_uri = data_uri.split(",")[1]
    with open(os.path.join(IMAGES_DIR, filename), "wb") as file_obj:
        file_obj.write(base64.b64decode(data_uri))


def post_with_csrf(url, data=None):
    csrf_token = get_csrf_token()
    headers = {"X-CSRFToken": csrf_token} if csrf_token else {}
    return session.post(url, data=data, headers=headers)


def get_grafico_comportamento(ip):
    data = {
        "ip_address": ip,
        "chart_type": "score_average",
        "action": "Baixar Gráfico",
    }
    resp = post_with_csrf(f"{BASE_URL}/graficos_comportamento/", data=data)
    if resp.status_code == 200 and "image/png" in resp.headers.get("Content-Type", ""):
        save_binary_response(resp, "comportamento_score_average.png")
        return True
    print(f"Erro comportamento: {resp.status_code} - {resp.text[:200]}")
    return False


def get_grafico_clusters():
    data = {
        "feature": "score_average_Mobat",
        "clusters": "3",
        "action": "Baixar Gráfico",
    }
    resp = post_with_csrf(f"{BASE_URL}/clusters/", data=data)
    if resp.status_code == 200 and "image/png" in resp.headers.get("Content-Type", ""):
        save_binary_response(resp, "clusters.png")
        return True
    print(f"Erro clusters: {resp.status_code} - {resp.text[:200]}")
    return False


def get_grafico_score_average_mobat():
    resp = post_with_csrf(f"{BASE_URL}/score_average_mobat/", data={"num_ips": "5"})
    if resp.status_code != 200:
        print(f"Erro ao post score_average: {resp.status_code}")
        return False

    resp = session.get(f"{BASE_URL}/score_average_mobat/?download=true")
    if resp.status_code == 200 and "image/png" in resp.headers.get("Content-Type", ""):
        save_binary_response(resp, "score_average_top_ips.png")
        return True
    print(f"Erro download score_average: {resp.status_code}")
    return False


def get_grafico_reputacao_pais():
    resp = post_with_csrf(
        f"{BASE_URL}/reputacao_pais/", data={"action": "Visualizar Todos os Países"}
    )
    if resp.status_code != 200:
        print(f"Erro ao post reputacao: {resp.status_code}")
        return False

    resp = session.get(f"{BASE_URL}/reputacao_pais/?download=true")
    if resp.status_code == 200 and "image/png" in resp.headers.get("Content-Type", ""):
        save_binary_response(resp, "reputacao_pais.png")
        return True
    print(f"Erro download reputacao: {resp.status_code}")
    return False


def get_heatmap():
    resp = post_with_csrf(f"{BASE_URL}/heatmap_ips/", data={"action": "Gerar HeatMap"})
    if resp.status_code == 200:
        match = re.search(r'<img[^>]+src="(data:image/png;base64,[^"]+)"', resp.text)
        if match:
            save_image_from_datauri(match.group(1), "heatmap.png")
            return True
    print(f"Erro heatmap: {resp.status_code}")
    return False


def generate_readme():
    readme = """# Mobat Project

Sistema de análise de reputação de endereços IP baseado em múltiplas fontes de inteligência de ameaças (AbuseIPDB, VirusTotal, IBM X-Force, AlienVault, Shodan). O projeto fornece visualizações, clusters, seleção de features e modelos de Machine Learning para classificar o risco de IPs.

## Tecnologias

- Django 4.2
- Python 3.12
- Pandas, Scikit-learn, XGBoost
- Matplotlib, Seaborn, GeoPandas
- SQLite (dados por semestre)

## Instalação e Execução com Docker

```bash
git clone <seu-repositorio>
cd mobat_project
docker compose build --no-cache
docker compose up
```

Acesse http://localhost:8000

## Funcionalidades

- Visualização de dados por semestre
- Gráficos de comportamento individual de IP
- Mapeamento de features (contagem de valores)
- Clustering não supervisionado
- Seleção de características (VarianceThreshold, SelectKBest, Lasso, Mutual Information)
- Importância de features com diferentes regressores
- Score médio Mobat por IP e por país
- Heatmap geográfico de ocorrências
- Tabela de acurácia comparando modelos com/sem seleção de features
- Download dos dados em diversos formatos (Excel, CSV, Parquet, JSON, XML, etc.)

## Exemplos de Gráficos Gerados

### Comportamento do Score Médio

![Comportamento do Score Médio](images/comportamento_score_average.png)

### Clusters

![Clusters](images/clusters.png)

### Top IPs com maior variação

![Top IPs com maior variação](images/score_average_top_ips.png)

### Reputação por País

![Reputação por País](images/reputacao_pais.png)

### Heatmap de ocorrências

![Heatmap de ocorrências](images/heatmap.png)

## Como usar

- Na página inicial, selecione o semestre desejado.
- Explore as abas de Gráficos de Comportamento, Clusters, Score Average Mobat, Reputação por País, Heatmap, Seleção de Características, Importância de Features, Tabela de Acurácia e Download de Tabela.

## Estrutura do Projeto

- `mobat_app/views/` - lógica por funcionalidade
- `mobat_app/utils/` - helpers para plotagem e ML
- `mobat_app/Seasons/` - bancos SQLite com dados semestrais
- `mobat_app/shapefiles/` - arquivos para mapas
"""

    with open("README.md", "w", encoding="utf-8") as file_obj:
        file_obj.write(readme)

    print("README.md gerado com sucesso!")


def main():
    print("Selecionando semestre e obtendo primeiro IP disponível...")
    ip = get_first_ip()
    if not ip:
        print(
            "Não foi possível obter um IP. Verifique se o servidor está rodando em http://127.0.0.1:8000 e se existe tabela com dados."
        )
        return

    print(f"IP selecionado: {ip}")

    print("Gerando gráfico de comportamento...")
    if get_grafico_comportamento(ip):
        print(" ✓ OK: comportamento_score_average.png")
    else:
        print(" ✗ Falha ao gerar gráfico de comportamento")

    print("Gerando gráfico de clusters...")
    if get_grafico_clusters():
        print(" ✓ OK: clusters.png")
    else:
        print(" ✗ Falha ao gerar clusters")

    print("Gerando gráfico de score average top IPs...")
    if get_grafico_score_average_mobat():
        print(" ✓ OK: score_average_top_ips.png")
    else:
        print(" ✗ Falha ao gerar score average top IPs")

    print("Gerando gráfico de reputação por país...")
    if get_grafico_reputacao_pais():
        print(" ✓ OK: reputacao_pais.png")
    else:
        print(" ✗ Falha ao gerar reputação por país")

    print("Gerando heatmap...")
    if get_heatmap():
        print(" ✓ OK: heatmap.png")
    else:
        print(" ✗ Falha ao gerar heatmap")

    generate_readme()
    print("\n✓ Processo concluído. README.md e imagens salvos na pasta 'images/'.")


if __name__ == "__main__":
    main()