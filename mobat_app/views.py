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
import matplotlib
matplotlib.use('Agg') 

def index(request):
    return render(request, 'index.html')

def visualizar_funcionalidades(request):
    table_choice = request.GET.get('table_choice')
    db_path = 'mobat_app/Seasons/PrimeiroSemestre.sqlite'
    if table_choice == '2':
        db_path = 'mobat_app/Seasons/SegundoSemestre.sqlite'
    elif table_choice == '3':
        db_path = 'mobat_app/Seasons/TerceiroSemestre.sqlite'
    elif table_choice == '4':
        db_path = 'mobat_app/Seasons/Total.sqlite'

    request.session['db_path'] = db_path

    table_name = None
    if table_choice == '1':
        table_name = 'PrimeiroSemestre'
    elif table_choice == '2':
        table_name = 'SegundoSemestre'
    elif table_choice == '3':
        table_name = 'TerceiroSemestre'
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

def plot_country_score_average(df, country):
    df_country = df[df['abuseipdb_country_code'] == country]

    if df_country.empty:
        return HttpResponse("Nenhum dado encontrado para o país selecionado.")

    plt.figure(figsize=(16, 8))
    bars = plt.bar(df_country['abuseipdb_country_code'], df_country['score_average_Mobat'], color='skyblue')
    plt.title('Reputação por País')
    plt.xlabel('País')
    plt.ylabel('Média do Score Average Mobat')
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y')
    for bar, score in zip(bars, df_country['score_average_Mobat']):
        yval = score + 0.1
        plt.text(bar.get_x() + bar.get_width()/2, yval, round(score, 2), ha='center', va='bottom', rotation=45)
    plt.tight_layout()
    plt.subplots_adjust(top=0.945, bottom=0.177, left=0.049, right=0.991, hspace=0.2, wspace=0.2)
    plt.show()

def reputacao_pais(request):
    if request.method == 'POST':
        country = request.POST.get('country')
        action = request.POST.get('action')
        if country == '' and action == 'Visualizar o País Escolhido':
            return HttpResponse("Por favor, selecione um país válido.")

        table_name = request.session.get('table_name')
        db_path = request.session.get('db_path')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
        conn.close()

        df = pd.DataFrame(data, columns=['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'])

        if action == 'Visualizar o País Escolhido':
            plot_country_score_average(df, country)
        elif action == 'Visualizar Todos os Países':
            # Lógica para mostrar todos os países
            # Chame uma função para plotar o gráfico de todos os países
            pass

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

def alpha2_to_alpha3(alpha2):
    country = pycountry.countries.get(alpha_2=alpha2)
    if country is not None:
        return country.alpha_3
    else:
        return None

def heatmap_ips(request):
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'Gerar HeatMap':
            table_name = request.session.get('table_name')
            if table_name is None:
                return redirect('index')

            db_path = request.session.get('db_path')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
            df = pd.DataFrame(data, columns=['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'])

            df_selected = df.dropna(subset=["abuseipdb_country_code"])
            serie_country_counts = df_selected["abuseipdb_country_code"].value_counts()
            min_count, max_count = serie_country_counts.min(), serie_country_counts.max()
            df_country_counts = serie_country_counts.rename_axis("country_code").reset_index(name="count")
            df_country_counts["country_code"] = df_country_counts["country_code"].apply(alpha2_to_alpha3)
            df_country_counts.dropna(subset=["country_code"], inplace=True)
            countries = set(df_country_counts["country_code"])
            SHAPEFILE = "mobat_app/shapefiles/ne_10m_admin_0_countries.shp"
            geo_df = gpd.read_file(SHAPEFILE)[["ADMIN", "ADM0_A3", "geometry"]]
            geo_df.columns = ["country", "country_code", "geometry"]
            geo_df = geo_df.drop(geo_df.loc[geo_df["country"] == "Antarctica"].index)
            geo_df = geo_df.merge(df_country_counts, on="country_code", how="left")
            geo_df["count"] = geo_df["count"].fillna(0)
            geo_df["normalized_count"] = (geo_df["count"] - min_count) / (max_count - min_count)
            fig, ax = plt.subplots(figsize=(20, 20))
            geo_df.plot(
                ax=ax,
                column="normalized_count",
                linewidth=0.5,
                cmap="Reds",
                legend=True,
                legend_kwds={"label": "Quantidade de Ocorrência Normalizada", "orientation": "horizontal"},
                edgecolor="gray",
            )
            plt.suptitle("Países com maior ocorrência de denúncias de IP", x=0.5, y=0.95, fontsize=20)
            plt.axis("off")
            plt.subplots_adjust(top=0.85, bottom=0.5, left=0.1, right=0.9, hspace=0.2, wspace=0.2)

            temp_file = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
            plt.savefig(temp_file.name)
            plt.close()

            image_path = temp_file.name
            conn.close()

            with open(image_path, "rb") as f:
                data_uri = f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"

            os.remove(image_path)

            context = {'image_path': data_uri}
            return render(request, 'heatmap_ips.html', context)

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
