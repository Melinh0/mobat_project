from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.conf import settings
import tempfile
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

            with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as temp_file:
                with pd.ExcelWriter(temp_file.name, engine='xlsxwriter') as writer:
                    for coluna, info in mapeamento.items():
                        info['contagem_valores'].to_excel(writer, sheet_name=info['sheet_name'], index=False)

                temp_file.seek(0)
                response = HttpResponse(temp_file.read(), content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
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
    if request.method == 'POST':
        file_type = request.POST.get('file_type')

        if file_type == 'excel' or file_type == 'csv':
            table_name = request.session.get('table_name')
            db_path = settings.BASE_DIR / request.session.get('db_path')

            conn = sqlite3.connect(db_path)
            df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)

            return download_all_ip_data(df, file_type)

    return render(request, 'upload_tabela_ips.html')

def download_all_ip_data(df, file_type):
    df_filled = df.fillna('None')
    if file_type == 'excel':
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.xlsx'
        df_filled.to_excel(response, index=False)
        return response
    elif file_type == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.csv'
        df_filled.to_csv(response, index=False)
        return response
    else:
        return HttpResponse("Tipo de arquivo inválido")

def heatmap_ips(request):
    print("HeatMap de Ocorrência dos Ips nos países")
    # Código para esta funcionalidade
    return render(request, 'heatmap_ips.html')

def tabela_acuracia(request):
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'Gerar Tabela':
            table_name = request.session.get('table_name')
            db_path = settings.BASE_DIR / request.session.get('db_path')

            conn = sqlite3.connect(db_path)
            df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)

            allowed_columns = [
                'abuseipdb_is_whitelisted',
                'abuseipdb_confidence_score',
                'abuseipdb_country_code',
                'abuseipdb_isp',
                'abuseipdb_domain',
                'abuseipdb_total_reports',
                'abuseipdb_num_distinct_users',
                'abuseipdb_last_reported_at',
                'virustotal_reputation',
                "virustotal_regional_internet_registry",
                'virustotal_as_owner',
                'harmless',
                'malicious',
                'suspicious',
                'undetected',
                'IBM_score',
                'IBM_average history Score',
                'IBM_most common score',
                'virustotal_asn',
                'SHODAN_asn',
                'SHODAN_isp',
                'ALIENVAULT_reputation',
                'ALIENVAULT_asn',
                'score_average_Mobat'
            ]

            results_df = plot_show_results_table(df, allowed_columns)
            results_html = results_df.to_html(classes="table table-striped table-bordered", index=False)
            request.session['results_html'] = results_html

            return render(request, 'tabela_acuracia.html', {'results_html': results_html})

    return render(request, 'tabela_acuracia.html', {'results_html': request.session.get('results_html')})

def categorize_non_numeric_columns(df):
    df = df.copy()
    for col in df.select_dtypes(include=['object', 'category']):
        if col != 'IP':
            df[col] = df[col].astype('category')
            df[col] = df[col].cat.codes
    return df

def preprocess_data(X):
    X = categorize_non_numeric_columns(X)
    X = handle_missing_values(X)
    return X

def handle_missing_values(X):
    return X.fillna(0)

def plot_show_results_table(df, allowed_columns):
    df = categorize_non_numeric_columns(df)
    X = df[allowed_columns]
    y = df['score_average_Mobat']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    X_train = preprocess_data(X_train)
    X_test = preprocess_data(X_test)
    
    vt = VarianceThreshold()
    start_time_vt = time.time()
    X_train_vt = vt.fit_transform(X_train)
    X_test_vt = vt.transform(X_test)
    end_time_vt = time.time()
    
    skb = SelectKBest(score_func=f_regression, k=5)
    start_time_skb = time.time()
    X_train_skb = skb.fit_transform(X_train, y_train)
    X_test_skb = skb.transform(X_test)
    end_time_skb = time.time()
    
    mrmr_5 = SelectKBest(score_func=mutual_info_regression, k=5)
    start_time_mrmr_5 = time.time()
    X_train_mrmr_5 = mrmr_5.fit_transform(X_train, y_train)
    X_test_mrmr_5 = mrmr_5.transform(X_test)
    end_time_mrmr_5 = time.time()
    
    mrmr_7 = SelectKBest(score_func=mutual_info_regression, k=7)
    start_time_mrmr_7 = time.time()
    X_train_mrmr_7 = mrmr_7.fit_transform(X_train, y_train)
    X_test_mrmr_7 = mrmr_7.transform(X_test)
    end_time_mrmr_7 = time.time()
    
    lasso = Lasso()
    start_time_lasso = time.time()
    lasso.fit(X_train, y_train)
    selected_features_lasso = X.columns[lasso.coef_ != 0]
    X_train_lasso = X_train[selected_features_lasso]
    X_test_lasso = X_test[selected_features_lasso]
    end_time_lasso = time.time()
    
    lr = LinearRegression()
    start_time_lr = time.time()
    lr.fit(X_train, y_train)
    selected_features_lr = X.columns[lr.coef_ != 0]
    X_train_lr = X_train[selected_features_lr]
    X_test_lr = X_test[selected_features_lr]
    end_time_lr = time.time()
    
    models = [
        ('GradientBoostingRegressor', GradientBoostingRegressor()),
        ('RandomForestRegressor', RandomForestRegressor()),
        ('ExtraTreesRegressor', ExtraTreesRegressor()),
        ('KNeighborsRegressor', KNeighborsRegressor()),
    ]
    
    results = []
    for name, model in models:
        start_time_model = time.time()
        model.fit(X_train, y_train)
        end_time_model = time.time()
        y_pred = model.predict(X_test)
        mse = mean_squared_error(y_test, y_pred)
        train_time = end_time_model - start_time_model
        results.append({'Model': name, 'Selection Technique': 'None', 'MSE': mse, 'Training Time': train_time})
    
    for name, model in models:
        for X_train_sel, X_test_sel, sel_name, start_time, end_time in [
            (X_train_vt, X_test_vt, 'VarianceThreshold', start_time_vt, end_time_vt),
            (X_train_skb, X_test_skb, 'SelectKBest', start_time_skb, end_time_skb),
            (X_train_mrmr_5, X_test_mrmr_5, 'MRMR-5', start_time_mrmr_5, end_time_mrmr_5),
            (X_train_mrmr_7, X_test_mrmr_7, 'MRMR-7', start_time_mrmr_7, end_time_mrmr_7),
            (X_train_lasso, X_test_lasso, 'Lasso', start_time_lasso, end_time_lasso),
            (X_train_lr, X_test_lr, 'LinearRegression', start_time_lr, end_time_lr)
        ]:
            start_time_model = time.time()
            model.fit(X_train_sel, y_train)
            end_time_model = time.time()
            y_pred = model.predict(X_test_sel)
            mse = mean_squared_error(y_test, y_pred)
            train_time = end_time_model - start_time_model
            results.append({'Model': name, 'Selection Technique': sel_name, 'MSE': mse, 'Training Time': train_time})
    
    results_df = pd.DataFrame(results)
    return results_df

def grafico_dispersao(request):
    allowed_columns = [
        'abuseipdb_is_whitelisted',
        'abuseipdb_confidence_score',
        'abuseipdb_total_reports',
        'abuseipdb_num_distinct_users',
        'virustotal_reputation',
        'harmless',
        'malicious',
        'suspicious',
        'undetected',
        'IBM_score',
        'IBM_average history Score',
        'IBM_most common score',
        'ALIENVAULT_reputation',
        'score_average_Mobat'
    ]

    if request.method == 'POST':
        x_axis = request.POST.get('x_axis')
        y_axis = request.POST.get('y_axis')

        if not x_axis or not y_axis:
            return render(request, 'grafico_dispersao.html', {'error': 'Por favor, selecione características para ambos os eixos.'})

        if x_axis not in allowed_columns or y_axis not in allowed_columns:
            return render(request, 'grafico_dispersao.html', {'error': 'As características selecionadas não são permitidas.'})

        table_name = request.session.get('table_name')

        if table_name is None:
            return redirect('index')

        db_path = request.session.get('db_path')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        columns_str = ", ".join([f'"{col}"' for col in allowed_columns])
        data = cursor.execute(f"SELECT {columns_str} FROM {table_name}").fetchall()
        df = pd.DataFrame(data, columns=allowed_columns)

        print("IBM_score:")
        print(df['IBM_score'])

        print("\nIBM_average history Score:")
        print(df['IBM_average history Score'])

        print("\nIBM_most common score:")
        print(df['IBM_most common score'])

        x_data = df[x_axis]
        y_data = df[y_axis]

        y_value_counts = y_data.value_counts()
        y_weights = y_data.map(y_value_counts)

        plt.figure(figsize=(18, 12))
        plt.scatter(x_data, y_data, s=y_weights*10, color='blue', alpha=0.6)
        plt.title(f'Dispersão: {x_axis} vs {y_axis}')
        plt.xlabel(x_axis)
        plt.ylabel(y_axis)
        plt.grid(True)
        plt.subplots_adjust(top=0.92, bottom=0.08, left=0.1, right=0.95, hspace=0.2, wspace=0.2)
        temp_file = os.path.join('/tmp', 'temp_plot.png')
        plt.savefig(temp_file)
        plt.close()

        with open(temp_file, "rb") as f:
            data_uri = f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"

        os.remove(temp_file)

        return render(request, 'grafico_dispersao.html', {'plot': data_uri})

    return render(request, 'grafico_dispersao.html')
