from django.shortcuts import render, redirect
from django.http import HttpResponse
import io
import pandas as pd
import matplotlib.pyplot as plt
import os
from sklearn.cluster import KMeans
from sklearn.feature_selection import VarianceThreshold, SelectKBest, f_classif, f_regression, mutual_info_regression
from sklearn.ensemble import GradientBoostingRegressor, RandomForestRegressor, ExtraTreesRegressor
from sklearn.linear_model import Lasso, LinearRegression
from sklearn.neighbors import KNeighborsRegressor
from sklearn.metrics import mean_squared_error
from sklearn.model_selection import train_test_split
import seaborn as sns
import numpy as np
import tkinter as tk
from tkinter import Tk, filedialog, ttk, messagebox
from matplotlib.lines import Line2D
import pytz
import geopandas as gpd
import pycountry
import time
import os
from sklearn.ensemble import AdaBoostRegressor
from xgboost import XGBRegressor
from sklearn.linear_model import ElasticNet
import sqlite3
import base64
import threading

def index(request):
    return render(request, 'index.html')

def visualizar_funcionalidades(request):
    table_choice = request.GET.get('table_choice')
    db_path = 'mobat_app/Seasons/PrimeiroSemestre2023'
    if table_choice == '2':
        db_path = 'mobat_app/Seasons/SegundoSemestre2023'
    elif table_choice == '3':
        db_path = 'mobat_app/Seasons/PrimeiroSemestre2024'
    elif table_choice == '4':
        db_path = 'mobat_app/Seasons/Total'

    request.session['db_path'] = db_path

    table_name = None
    if table_choice == '1':
        table_name = 'PrimeiroSemestre2023'
    elif table_choice == '2':
        table_name = 'SegundoSemestre2023'
    elif table_choice == '3':
        table_name = 'PrimeiroSemestre2024'
    elif table_choice == '4':
        table_name = 'Total'

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
    context = {'data': data}

    request.session['table_name'] = table_name
    return render(request, 'visualizar_funcionalidades.html', context)

def graficos_comportamento(request):
    print("Gráficos de Comportamento")
    # Aqui você pode adicionar o código específico para essa funcionalidade
    return render(request, 'graficos_comportamento.html')

def mapeamento_features(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        feature = request.POST.get('feature')

        if action == 'Mapear Feature' and feature:
            table_name = request.session.get('table_name')

            if table_name is None:
                return redirect('index')

            db_path = request.session.get('db_path')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
            df = pd.DataFrame(data, columns=['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'])

            value_counts = df[feature].value_counts().nlargest(5)
            plt.figure(figsize=(16, 8))
            x_values = [str(val) for val in value_counts.index]
            bars = plt.bar(x_values, value_counts.values, color='skyblue')
            plt.ylabel('Quantidade')
            plt.title(f'Gráfico de Barras - {feature} (Top 5 Valores)')
            plt.xticks(rotation=45, ha='right')
            for bar, valor in zip(bars, value_counts.values):
                plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, str(valor), ha='center', va='bottom')
            plt.subplots_adjust(top=0.94, bottom=0.215, left=0.125, right=0.9, hspace=0.2, wspace=0.2)
            temp_file = os.path.join('/tmp', 'temp_plot.png')
            plt.savefig(temp_file)
            plt.close()

            with open(temp_file, "rb") as f:
                data_uri = f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"

            os.remove(temp_file)

            return render(request, 'mapeamento_features.html', {'plot': data_uri})

        elif action == 'Baixar Todas as Features Mapeadas':
            db_path = request.session.get('db_path')

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            table_name = request.session.get('table_name')

            if table_name is None:
                return HttpResponse("Tabela não selecionada")

            data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
            df = pd.DataFrame(data, columns=['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'])

            mapeamento = {}
            for coluna in df.columns:
                contagem_valores = df[coluna].value_counts().reset_index()
                contagem_valores.columns = [coluna, 'Quantidade']
                sheet_name = coluna[:31]
                mapeamento[coluna] = {'contagem_valores': contagem_valores, 'sheet_name': sheet_name}

            buffer = io.BytesIO()
            with pd.ExcelWriter(buffer, engine='xlsxwriter') as writer:
                for coluna, info in mapeamento.items():
                    info['contagem_valores'].to_excel(writer, sheet_name=info['sheet_name'], index=False)
            buffer.seek(0)

            response = HttpResponse(buffer, content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
            response['Content-Disposition'] = 'attachment; filename="features_mapeadas.xlsx"'
            return response

    return render(request, 'mapeamento_features.html')

def plot_grafico():
    plt.figure(figsize=(16, 8))
    # Código de plotagem do gráfico aqui
    plt.show()

def clusters(request):
    print("Clusters")
    # Código para esta funcionalidade
    return render(request, 'clusters.html')

def selecao_caracteristicas(request):
    print("Seleção de Características")
    # Código para esta funcionalidade
    return render(request, 'selecao_caracteristicas.html')

def importancias_ml(request):
    print("Importâncias para Machine Learning")
    # Código para esta funcionalidade
    return render(request, 'importancias_ml.html')

def score_average_mobat(request):
    print("Score Average Mobat dos IPs com maior variação")
    # Código para esta funcionalidade
    return render(request, 'score_average_mobat.html')

def reputacao_pais(request):
    print("Reputação por País")
    # Código para esta funcionalidade
    return render(request, 'reputacao_pais.html')

def upload_tabela_ips(request):
    print("Upload da Tabela dos Ips do período")
    # Código para esta funcionalidade
    return render(request, 'upload_tabela_ips.html')

def heatmap_ips(request):
    print("HeatMap de Ocorrência dos Ips nos países")
    # Código para esta funcionalidade
    return render(request, 'heatmap_ips.html')

def tabela_acuracia(request):
    print("Tabela de Acurácia e Tempo de Treinamento dos Modelos")
    # Código para esta funcionalidade
    return render(request, 'tabela_acuracia.html')

def grafico_dispersao(request):
    print("Gráfico de Dispersão")
    # Código para esta funcionalidade
    return render(request, 'grafico_dispersao.html')
