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

os.environ["OMP_NUM_THREADS"] = "1"

plt.style.use('dark_background')

def extract_ip(ip_with_timestamp):
    ip = ip_with_timestamp.split()[0]
    if ip.endswith('_'):
        ip = ip[:-1]  
    return ip

def plot_ip_data(df, ip, mean_values):
    plot_ip_location(df, ip)
    plot_ip_reports(df, ip, mean_values)
    plot_ip_score_average(df, ip, mean_values)
    plot_ip_last_report(df, ip)
    plot_ip_time_period(df, ip)
    plot_ibm_scores(df, ip, mean_values)
    plot_ip_virustotal_stats(df, ip, mean_values)
    root = tk.Tk()
    root.withdraw()
    download_data = tk.messagebox.askyesno("Download de Dados", f"Deseja baixar os dados do IP {ip} em Excel?")
    if download_data:
        download_ip_data(df, ip)

def download_ip_data(df, ip):
    ip_data = df[df['IP'] == ip]
    ip_data = ip_data.replace('', None)
    ip_data = ip_data.fillna('None')
    if not ip_data.empty:
        root = tk.Tk()
        root.withdraw()
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            file_name = f"{ip}_data.xlsx"
            file_path = os.path.join(folder_selected, file_name)
            ip_data.to_excel(file_path, index=False)
            print(f"Dados do IP {ip} foram salvos no arquivo {file_path}")
        else:
            print("Nenhum diretório selecionado")
    else:
        print(f"Nenhum dado encontrado para o IP {ip}")

def alpha2_to_alpha3(alpha2):
    try:
        return pycountry.countries.get(alpha_2=alpha2).alpha_3
    except AttributeError:
        return None

def plot_country_heatmap(df):
    df_selected = df.dropna(subset=["abuseipdb_country_code"])
    serie_country_counts = df_selected["abuseipdb_country_code"].value_counts()
    min_count, max_count = serie_country_counts.min(), serie_country_counts.max()
    df_country_counts = serie_country_counts.rename_axis("country_code").reset_index(name="count")
    df_country_counts["country_code"] = df_country_counts["country_code"].apply(
        alpha2_to_alpha3
    )
    df_country_counts.dropna(subset=["country_code"], inplace=True)
    countries = set(df_country_counts["country_code"])
    SHAPEFILE = r"mobat_app\shapefiles\ne_10m_admin_0_countries.shp"
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
    plt.suptitle("Heatmap das Ocorrências dos Países", x=0.5, y=0.95, fontsize=20)
    plt.axis("off")
    plt.subplots_adjust(top=0.88, bottom=0, left=0.125, right=0.9, hspace=0.2, wspace=0.2)
    plt.show()
    root = Tk()
    root.withdraw()
    download = input("Deseja salvar o arquivo Excel com as quantidades de ocorrências dos países? (y/n): ")
    if download.lower() == 'y':
        file_path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx")])
        if file_path:
            df_country_counts.to_excel(file_path, index=False)
            print(f"Excel file saved to {file_path}")

def plot_country_score_average(df):
    country_names = {
        'US': 'Estados Unidos',
        'CN': 'China',
        'SG': 'Singapura',
        'DE': 'Alemanha',
        'VN': 'Vietnã',
        'KR': 'Coreia do Sul',
        'IN': 'Índia',
        'RU': 'Rússia',
        'LT': 'Lituânia',
        'TW': 'Taiwan',
        'GB': 'Reino Unido',
        'JP': 'Japão',
        'IR': 'Irã',
        'BR': 'Brasil',
        'AR': 'Argentina',
        'NL': 'Holanda',
        'TH': 'Tailândia',
        'CA': 'Canadá',
        'PK': 'Paquistão',
        'ID': 'Indonésia',
        'ET': 'Etiópia',
        'FR': 'França',
        'BG': 'Bulgária',
        'PA': 'Panamá',
        'SA': 'Arábia Saudita',
        'BD': 'Bangladesh',
        'HK': 'Hong Kong',
        'MA': 'Marrocos',
        'EG': 'Egito',
        'UA': 'Ucrânia',
        'MX': 'México',
        'UZ': 'Uzbequistão',
        'ES': 'Espanha',
        'AU': 'Austrália',
        'CO': 'Colômbia',
        'KZ': 'Cazaquistão',
        'EC': 'Equador',
        'BZ': 'Belize',
        'SN': 'Senegal',
        'None': 'None',
        'IE': 'Irlanda',
        'FI': 'Finlândia',
        'ZA': 'África do Sul',
        'IT': 'Itália',
        'PH': 'Filipinas',
        'CR': 'Costa Rica',
        'CH': 'Suíça'
    }

    country_avg_scores = df.groupby('abuseipdb_country_code')['score_average_Mobat'].mean().sort_values(ascending=False)
    country_avg_scores.index = country_avg_scores.index.map(country_names)
    mean_of_means = country_avg_scores.mean()
    country_avg_scores = country_avg_scores[~country_avg_scores.index.isna()]
    plt.figure(figsize=(16, 8)) 
    bars = plt.bar(country_avg_scores.index.astype(str), country_avg_scores.values, color='skyblue')
    plt.axhline(mean_of_means, linestyle='--', color='red', label=f'Média das médias: {mean_of_means:.2f}')
    plt.title('Reputação por País')
    plt.xlabel('País')
    plt.ylabel('Média do Score Average Mobat')
    plt.xticks(rotation=45, ha='right')
    handles, labels = plt.gca().get_legend_handles_labels()
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='Score > MeanScore: Benigno\nScore < MeanScore: Malicioso')]
    plt.legend(handles=handles + extra_handles, loc='upper right')
    plt.grid(axis='y')
    for bar, score in zip(bars, country_avg_scores.values):
        yval = score + 0.1 
        plt.text(bar.get_x() + bar.get_width()/2, yval, round(score, 2), ha='center', va='bottom', rotation=45)
    plt.tight_layout()
    plt.subplots_adjust(top=0.945, bottom=0.177, left=0.049, right=0.991, hspace=0.2, wspace=0.2)
    plt.show()

def plot_ip_location(df, ip):
    ip_data = df[df['IP'] == ip]
    plt.figure(figsize=(16, 8))
    country_names = {
        'US': 'Estados Unidos',
        'CN': 'China',
        'SG': 'Singapura',
        'DE': 'Alemanha',
        'VN': 'Vietnã',
        'KR': 'Coreia do Sul',
        'IN': 'Índia',
        'RU': 'Rússia',
        'LT': 'Lituânia',
        'TW': 'Taiwan',
        'GB': 'Reino Unido',
        'JP': 'Japão',
        'IR': 'Irã',
        'BR': 'Brasil',
        'AR': 'Argentina',
        'NL': 'Holanda',
        'TH': 'Tailândia',
        'CA': 'Canadá',
        'PK': 'Paquistão',
        'ID': 'Indonésia',
        'ET': 'Etiópia',
        'FR': 'França',
        'BG': 'Bulgária',
        'PA': 'Panamá',
        'SA': 'Arábia Saudita',
        'BD': 'Bangladesh',
        'HK': 'Hong Kong',
        'MA': 'Marrocos',
        'EG': 'Egito',
        'UA': 'Ucrânia',
        'MX': 'México',
        'UZ': 'Uzbequistão',
        'ES': 'Espanha',
        'AU': 'Austrália',
        'CO': 'Colômbia',
        'KZ': 'Cazaquistão',
        'EC': 'Equador',
        'BZ': 'Belize',
        'SN': 'Senegal',
        'None': 'None',
        'IE': 'Irlanda',
        'FI': 'Finlândia',
        'ZA': 'África do Sul',
        'IT': 'Itália',
        'PH': 'Filipinas',
        'CR': 'Costa Rica',
        'CH': 'Suíça'
    }
    plt.plot(range(len(ip_data)), ip_data['abuseipdb_country_code'].map(country_names), label='AbuseIPDB Country')
    plt.plot(range(len(ip_data)), ip_data['abuseipdb_isp'], label='AbuseIPDB ISP')
    plt.plot(range(len(ip_data)), ip_data['abuseipdb_domain'], label='AbuseIPDB Domain')
    plt.plot(range(len(ip_data)), ip_data['virustotal_as_owner'], label='VirusTotal AS Owner')
    plt.plot(range(len(ip_data)), ip_data['virustotal_asn'], label='VirusTotal ASN')
    plt.plot(range(len(ip_data)), ip_data['ALIENVAULT_asn'], label='ALIENVAULT ASN')
    plt.title(f'Comportamento do IP {ip} em relação a localização')
    plt.ylabel('Valor')
    plt.xlabel('Registros ao longo do tempo')
    plt.legend()   
    plt.grid(True)
    plt.gca().xaxis.grid(True, linestyle='--')  
    plt.xticks(range(len(ip_data)), range(1, len(ip_data)+1), rotation=90)  
    plt.gca().xaxis.set_label_coords(0.5, -0.1)
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.205, right=0.96, hspace=0.2, wspace=0.2)
    plt.show()

def plot_ip_reports(df, ip, mean_values):
    ip_data = df[df['IP'] == ip].reset_index(drop=True)
    plt.figure(figsize=(16, 8))
    plt.plot(ip_data.index, ip_data['abuseipdb_total_reports'], label='Total Reports', color='blue')
    plt.plot(ip_data.index, ip_data['abuseipdb_num_distinct_users'], label='Distinct Users', color='yellow')
    mean_total_reports = mean_values['abuseipdb_total_reports']
    mean_distinct_users = mean_values['abuseipdb_num_distinct_users']
    plt.axhline(y=mean_total_reports, color='skyblue', linestyle='--', label='Mean Total Reports')
    plt.axhline(y=mean_distinct_users, color='y', linestyle='--', label='Mean Distinct Users')
    min_score = ip_data['abuseipdb_total_reports'].min()
    max_score = ip_data['abuseipdb_total_reports'].max()
    plt.fill_between(ip_data.index, min_score, max_score, alpha=0.3, color='skyblue', label=f'Score Range: {min_score:.2f} - {max_score:.2f}')
    min_score = ip_data['abuseipdb_num_distinct_users'].min()
    max_score = ip_data['abuseipdb_num_distinct_users'].max()
    plt.fill_between(ip_data.index, min_score, max_score, alpha=0.3, color='y', label=f'Score Range: {min_score:.2f} - {max_score:.2f}')
    plt.text(0, mean_total_reports, f'Mean Total Reports: {mean_total_reports:.2f}', va='bottom', ha='left', color='skyblue', fontweight='bold')
    plt.text(0, mean_distinct_users, f'Mean Distinct Users: {mean_distinct_users:.2f}', va='bottom', ha='left', color='y', fontweight='bold')
    plt.title(f'Comportamento do IP {ip} em relação ao total de reports e usuários distintos')
    plt.ylabel('Valor')
    plt.xlabel('Registros ao longo do tempo')
    plt.legend()
    plt.grid(True)
    plt.gca().yaxis.grid(True, linestyle=' ')
    plt.gca().xaxis.grid(True, linestyle='--')
    plt.gca().xaxis.set_label_coords(0.5, -0.1)
    plt.xticks(range(len(ip_data)), range(1, len(ip_data)+1), rotation=90)  
    handles, labels = plt.gca().get_legend_handles_labels()
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='\nReports > MeanScore: Malicioso\nReports < MeanScore: Benigno')]
    plt.legend(handles=handles + extra_handles, loc='upper right')
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.205, right=0.96, hspace=0.2, wspace=0.2)
    plt.show()

def plot_dispersion_ip_reports(df, treat_all_as_string=False):
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

    while True:
        print("Características disponíveis para os eixos x e y:")
        for i, col in enumerate(allowed_columns):
            print(f"{i+1}. {col}")
        print("0. Voltar ao menu")
        x_choice = int(input("Escolha a característica para o eixo x (digite o número correspondente): "))
        if x_choice == 0:
            break
        if 1 <= x_choice <= len(allowed_columns):
            x_feature = allowed_columns[x_choice - 1]
        else:
            print("Escolha inválida. Por favor, escolha um número válido ou 0 para voltar ao menu.")
            continue
        y_choice = int(input("Escolha a característica para o eixo y (digite o número correspondente): "))
        if y_choice == 0:
            break
        if 1 <= y_choice <= len(allowed_columns) and y_choice != x_choice:
            y_feature = allowed_columns[y_choice - 1]
        elif y_choice == x_choice:
            print("A característica escolhida para o eixo y deve ser diferente da escolhida para o eixo x.")
            continue
        else:
            print("Escolha inválida. Por favor, escolha um número válido e diferente da escolha para o eixo x ou 0 para voltar ao menu.")
            continue
        
        if treat_all_as_string:
            if x_feature not in df.columns or y_feature not in df.columns:
                print("Erro: As características selecionadas não estão presentes no DataFrame.")
                continue
            x_data = df[x_feature].astype(str)
            y_data = df[y_feature].astype(str)
        else:
            x_data = df[x_feature]
            y_data = df[y_feature]

        if x_feature == 'abuseipdb_last_reported_at':
            x_data = pd.to_datetime(x_data, errors='coerce')
            mask = x_data.notna()
            x_data = x_data[mask]
            y_data = y_data[mask]

        y_value_counts = y_data.value_counts()
        y_weights = y_data.map(y_value_counts)

        plt.figure(figsize=(18, 12))
        plt.scatter(x_data, y_data, s=y_weights*10, color='blue', alpha=0.6)
        plt.title(f'Dispersão: {x_feature} vs {y_feature}')
        plt.xlabel(x_feature)
        plt.ylabel(y_feature)
        plt.legend()
        plt.grid(True)
        plt.subplots_adjust(top=0.92, bottom=0.08, left=0.1, right=0.95, hspace=0.2, wspace=0.2)
        plt.show()

def plot_ip_score_average(df, ip, mean_values):
    ip_data = df[df['IP'] == ip].reset_index(drop=True)
    plt.figure(figsize=(16, 8))
    plt.plot(ip_data.index, ip_data['score_average_Mobat'])
    mean_score_average = mean_values['score_average_Mobat']
    plt.axhline(y=mean_score_average, color='skyblue', linestyle='--', label=f'Mean Score Average Mobat: {mean_score_average:.2f}')
    min_score = ip_data['score_average_Mobat'].min()
    max_score = ip_data['score_average_Mobat'].max()
    plt.fill_between(ip_data.index, min_score, max_score, alpha=0.3, color='skyblue', label=f'Score Range: {min_score:.2f} - {max_score:.2f}')
    plt.text(0, mean_score_average, f'Mean Score Average Mobat: {mean_score_average:.2f}', va='bottom', ha='left', color='skyblue', fontweight='bold')
    plt.title(f'Comportamento do IP {ip} em relação ao Score Average Mobat')
    plt.ylabel('Score Average Mobat')
    plt.xlabel('Registros ao longo do tempo')
    plt.grid(True)
    plt.gca().yaxis.grid(True, linestyle=' ')
    plt.gca().xaxis.grid(True, linestyle='--')
    plt.gca().xaxis.set_label_coords(0.5, -0.1)
    plt.xticks(range(len(ip_data)), range(1, len(ip_data)+1), rotation=90)  
    handles, labels = plt.gca().get_legend_handles_labels()
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='\nScore > MeanScore: Benigno\nScore < MeanScore: Malicioso')]
    plt.legend(handles=handles + extra_handles, loc='upper right')
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.08, right=0.855, hspace=0.2, wspace=0.2)
    plt.show()

def plot_ibm_scores(df, ip, mean_values):
    ip_data = df[df['IP'] == ip].reset_index(drop=True)
    plt.figure(figsize=(16, 8))
    plt.plot(ip_data.index, ip_data['IBM_score'], label='IBM Score', color='blue')
    plt.plot(ip_data.index, ip_data['IBM_average history Score'], label='IBM Average History Score', color='yellow')
    plt.plot(ip_data.index, ip_data['IBM_most common score'], label='IBM Most Common Score', color='green')
    mean_IBM_score = mean_values['IBM_score']
    mean_IBM_average = mean_values['IBM_average history Score']
    mean_IBM_most_common = mean_values['IBM_most common score']
    plt.axhline(y=mean_IBM_score, color='skyblue', linestyle='--', label='Mean IBM Score')
    plt.axhline(y=mean_IBM_average, color='y', linestyle='--', label='Mean IBM Average History Score')
    plt.axhline(y=mean_IBM_most_common, color='lightgreen', linestyle='--', label='Mean IBM Most Common Score')
    min_score = ip_data['IBM_score'].min()
    max_score = ip_data['IBM_score'].max()
    plt.fill_between(ip_data.index, min_score, max_score, alpha=0.3, color='skyblue', label=f'Score Range: {min_score:.2f} - {max_score:.2f}')
    min_score = ip_data['IBM_average history Score'].min()
    max_score = ip_data['IBM_average history Score'].max()
    plt.fill_between(ip_data.index, min_score, max_score, alpha=0.3, color='y', label=f'Score Range: {min_score:.2f} - {max_score:.2f}')
    min_score = ip_data['IBM_most common score'].min()
    max_score = ip_data['IBM_most common score'].max()
    plt.fill_between(ip_data.index, min_score, max_score, alpha=0.3, color='lightgreen', label=f'Score Range: {min_score:.2f} - {max_score:.2f}')
    plt.text(0, mean_IBM_score, f'Mean IBM Score: {mean_IBM_score:.2f}', va='bottom', ha='left', color='skyblue', fontweight='bold')
    plt.text(0, mean_IBM_average, f'Mean IBM Average History Score: {mean_IBM_average:.2f}', va='bottom', ha='left', color='y', fontweight='bold')
    plt.text(0, mean_IBM_most_common, f'Mean IBM Most Common Score: {mean_IBM_most_common:.2f}', va='bottom', ha='left', color='lightgreen', fontweight='bold')
    plt.title(f'Comportamento do IP {ip} em relação aos scores da IBM')
    plt.ylabel('Valor')
    plt.xlabel('Registros ao longo do tempo')
    plt.legend()
    plt.grid(True)
    plt.gca().yaxis.grid(True, linestyle=' ')
    plt.gca().xaxis.grid(True, linestyle='--')
    plt.gca().xaxis.set_label_coords(0.5, -0.1)
    plt.xticks(range(len(ip_data)), range(1, len(ip_data)+1), rotation=90)  
    handles, labels = plt.gca().get_legend_handles_labels()
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='\nScore > MeanScore: Benigno\nScore < MeanScore: Malicioso')]
    plt.legend(handles=handles + extra_handles, loc='upper right')
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.18, right=0.9, hspace=0.2, wspace=0.2)
    plt.show()

def plot_ip_virustotal_stats(df, ip, mean_values):
    ip_data = df[df['IP'] == ip].reset_index(drop=True)
    plt.figure(figsize=(16, 8))
    plt.plot(ip_data.index, ip_data['virustotal_reputation'], label='virustotal_reputation')
    mean_virustotal_reputation = mean_values['virustotal_reputation']
    plt.axhline(y=mean_virustotal_reputation, color='skyblue', linestyle='--', label='Mean VirusTotal Reputation')
    min_score = ip_data['virustotal_reputation'].min()
    max_score = ip_data['virustotal_reputation'].max()
    plt.fill_between(ip_data.index, min_score, max_score, alpha=0.3, color='skyblue', label=f'Score Range: {min_score:.2f} - {max_score:.2f}')
    plt.text(0, mean_virustotal_reputation, f'Mean VirusTotal Reputation: {mean_virustotal_reputation:.2f}', va='bottom', ha='left', color='skyblue', fontweight='bold')
    plt.title(f'Comportamento do IP {ip} em relação às estatísticas do VirusTotal')
    plt.ylabel('Valor')
    plt.xlabel('Registros ao longo do tempo')
    plt.legend()
    plt.grid(True)
    plt.gca().yaxis.grid(True, linestyle=' ')
    plt.gca().xaxis.grid(True, linestyle='--')
    plt.gca().xaxis.set_label_coords(0.5, -0.1)
    plt.xticks(range(len(ip_data)), range(1, len(ip_data)+1), rotation=90)  
    handles, labels = plt.gca().get_legend_handles_labels()
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='\nScore > MeanScore: Benigno\nScore < MeanScore: Malicioso')]
    plt.legend(handles=handles + extra_handles, loc='upper right')
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.18, right=0.9, hspace=0.2, wspace=0.2)
    plt.show()

fusos_paises = {
    'CN': 'Asia/Shanghai',
    'US': 'America/New_York',
    'SG': 'Asia/Singapore',
    'IN': 'Asia/Kolkata',
    'LT': 'Europe/Vilnius',
    'DE': 'Europe/Berlin',
    'GB': 'Europe/London',
    'KR': 'Asia/Seoul',
    'RU': 'Europe/Moscow',
    'VN': 'Asia/Ho_Chi_Minh',
    'CA': 'America/Toronto',
    'TW': 'Asia/Taipei',
    'JP': 'Asia/Tokyo',
    'BR': 'America/Sao_Paulo',
    'NL': 'Europe/Amsterdam',
    'TH': 'Asia/Bangkok',
    'MX': 'America/Mexico_City',
    'UZ': 'Asia/Tashkent',
    'UA': 'Europe/Kiev',
    'BD': 'Asia/Dhaka',
    'AR': 'America/Argentina/Buenos_Aires',
    'IR': 'Asia/Tehran',
    'ET': 'Africa/Addis_Ababa',
    'BG': 'Europe/Sofia',
    'MA': 'Africa/Casablanca',
    'EG': 'Africa/Cairo',
    'ES': 'Europe/Madrid',
    'HK': 'Asia/Hong_Kong',
    'ID': 'Asia/Jakarta',
    'FR': 'Europe/Paris',
    'ZA': 'Africa/Johannesburg',
    'PH': 'Asia/Manila',
    'CH': 'Europe/Zurich',
    'IT': 'Europe/Rome',
    'CR': 'America/Costa_Rica',
    'IE': 'Europe/Dublin',
    'AT': 'Europe/Vienna',
    'AU': 'Australia/Sydney',
    'FI': 'Europe/Helsinki',
    'PK': 'Asia/Karachi',
    'SA': 'Asia/Riyadh',
    'PA': 'America/Panama',
    'KZ': 'Asia/Almaty',
    'CO': 'America/Bogota',
    'EC': 'America/Guayaquil',
    'SN': 'Africa/Dakar',
    'BZ': 'America/Belize'
}

def plot_ip_last_report(df, ip):
    ip_data = df[df['IP'] == ip].copy()
    ip_data['abuseipdb_last_reported_at'] = pd.to_datetime(ip_data['abuseipdb_last_reported_at'], errors='coerce')
    ip_data = ip_data.sort_values(by='abuseipdb_last_reported_at')
    ip_data = ip_data[ip_data['abuseipdb_last_reported_at'].notna()]
    def convert_to_timezone(row):
        timezone_pais = fusos_paises.get(row['abuseipdb_country_code'])
        if timezone_pais:
            fuso_pais = pytz.timezone(timezone_pais)
            return row['abuseipdb_last_reported_at'].astimezone(fuso_pais)
        return row['abuseipdb_last_reported_at']
    ip_data['abuseipdb_last_reported_at'] = ip_data.apply(convert_to_timezone, axis=1)
    plt.figure(figsize=(16, 8))
    plt.plot(range(len(ip_data)), ip_data['abuseipdb_last_reported_at'], label='AbuseIPDB Last Reported At')
    plt.title(f'Comportamento do IP {ip} em relação ao último relatório do AbuseIPDB')
    plt.ylabel('Timestamp(EUA)')
    plt.xlabel('Registros ao longo do tempo')
    plt.legend()
    plt.grid(True)
    plt.gca().xaxis.grid(True, linestyle='--')
    plt.gca().xaxis.set_label_coords(0.5, -0.1)
    plt.xticks(range(len(ip_data)), range(1, len(ip_data)+1), rotation=90)
    plt.yticks(ip_data['abuseipdb_last_reported_at'], ip_data['abuseipdb_last_reported_at'].apply(lambda x: str(x)))
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.18, right=0.9, hspace=0.2, wspace=0.2)
    plt.show()

def plot_ip_time_period(df, ip):
    ip_data = df[df['IP'] == ip].copy()
    ip_data['abuseipdb_last_reported_at'] = pd.to_datetime(ip_data['abuseipdb_last_reported_at'], errors='coerce')
    ip_data = ip_data.sort_values(by='abuseipdb_last_reported_at')
    ip_data = ip_data[ip_data['abuseipdb_last_reported_at'].notna()]
    def convert_to_timezone(row):
        timezone_pais = fusos_paises.get(row['abuseipdb_country_code'])
        if timezone_pais:
            fuso_pais = pytz.timezone(timezone_pais)
            return row['abuseipdb_last_reported_at'].astimezone(fuso_pais)
        return row['abuseipdb_last_reported_at']
    ip_data['abuseipdb_last_reported_at'] = ip_data.apply(convert_to_timezone, axis=1)
    morning = ip_data[(ip_data['abuseipdb_last_reported_at'].dt.hour >= 5) & (ip_data['abuseipdb_last_reported_at'].dt.hour < 12)]
    afternoon = ip_data[(ip_data['abuseipdb_last_reported_at'].dt.hour >= 12) & (ip_data['abuseipdb_last_reported_at'].dt.hour < 18)]
    night = ip_data[(ip_data['abuseipdb_last_reported_at'].dt.hour >= 18) | (ip_data['abuseipdb_last_reported_at'].dt.hour < 5)]
    time_periods = ['Manhã', 'Tarde', 'Noite']
    counts = [len(morning), len(afternoon), len(night)]
    plt.figure(figsize=(16, 8))
    plt.bar(time_periods, counts, color=['skyblue', 'orange', 'green'])
    plt.title(f'Períodos do Dia com mais ocorrência de report do IP {ip}')
    plt.xlabel('Período do Dia')
    plt.ylabel('Ocorrências')
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.18, right=0.9, hspace=0.2, wspace=0.2)
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='Manhã corresponde a 5 horas até 12 horas\nTarde corresponde a 12 horas até 18 horas\nNoite corresponde a 18 horas até 5 horas')]
    plt.legend(handles=extra_handles, loc='lower right')
    plt.grid(axis='y')
    plt.show()

def plot_feature_mapping(df):
    for column in df.columns:
        plt.figure(figsize=(16, 8))
        value_counts = df[column].value_counts().nlargest(5)
        x_values = [str(val) for val in value_counts.index]
        bars = plt.bar(x_values, value_counts.values, color='skyblue')
        plt.ylabel('Quantidade')
        plt.title(f'Gráfico de Barras - {column} (Top 5 Valores)')
        plt.xticks(rotation=45, ha='right')
        for bar, valor in zip(bars, value_counts.values):
            plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, str(valor), ha='center', va='bottom')
        plt.subplots_adjust(top=0.94, bottom=0.215, left=0.125, right=0.9, hspace=0.2, wspace=0.2)
        plt.show()
    salvar = input("Deseja salvar o mapeamento em um arquivo Excel? (s/n): ")
    if salvar.lower() == 's':
        mapping_features_download_excel(df)

def mapping_features_download_excel(df):
    mapeamento = {}
    for coluna in df.columns:
        contagem_valores = df[coluna].value_counts().reset_index()
        contagem_valores.columns = [coluna, 'Quantidade']
        sheet_name = coluna[:31]
        mapeamento[coluna] = {'contagem_valores': contagem_valores, 'sheet_name': sheet_name}
    root = tk.Tk()
    root.withdraw()
    arquivo_excel_saida = filedialog.asksaveasfilename(title="Salvar como", defaultextension=".xlsx",
                                                 filetypes=[("Arquivos Excel", "*.xlsx")])
    if arquivo_excel_saida:
        with pd.ExcelWriter(arquivo_excel_saida, engine='xlsxwriter') as writer:
            for coluna, info in mapeamento.items():
                info['contagem_valores'].to_excel(writer, sheet_name=info['sheet_name'], index=False)
        print(f'Mapeamento salvo em {arquivo_excel_saida}')
    else:
        print("Nenhum arquivo selecionado")
 
def categorize_non_numeric_columns(df):
    df = df.copy()  
    for col in df.select_dtypes(include=['object', 'category']):
        if col != 'IP':
            df[col] = df[col].astype('category')
            df[col] = df[col].cat.codes
    return df

def plot_clusters(df):
    allowed_columns = [
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
    while True:
        print("Features disponíveis:")
        for i, feature in enumerate(allowed_columns):
            print(f"{i+1}. {feature}")
        print("0. Voltar ao menu")
        choice = int(input("Escolha uma feature (Insira o número correspondente): ")) - 1
        if choice == -1:
            break

        selected_feature = allowed_columns[choice]
        X = df[[selected_feature]]
        num_clusters = int(input("Digite a quantidade de clusters que deseja visualizar: "))
        if num_clusters <= 0:
            print("O número de clusters deve ser maior que zero.")
            continue
        
        kmeans = KMeans(n_clusters=num_clusters, random_state=0, n_init=10).fit(X)
        df['cluster'] = kmeans.labels_
        mean_feature_all = df[selected_feature].mean()
        plt.figure(figsize=(16, 8))
        labels = []
        for cluster in df['cluster'].unique():
            cluster_data = df[df['cluster'] == cluster]
            plt.scatter(cluster_data.index, cluster_data[selected_feature], label=f'Cluster {cluster}')
            unique_ips = cluster_data['IP'].nunique()
            labels.append(f'Cluster {cluster} [Num. of Unique IPs: {unique_ips}]')
        labels.append(f'Mean {selected_feature} All: {mean_feature_all:.2f}')
        plt.axhline(y=mean_feature_all, color='r', linestyle='--', label=f'Mean {selected_feature} All: {mean_feature_all:.2f}')
        plt.title(f'Clusters da coluna "{selected_feature}"')
        plt.ylabel(selected_feature)
        plt.legend(labels=labels)
        plt.grid(True)
        plt.subplots_adjust(top=0.93, bottom=0.14, left=0.105, right=0.915, hspace=0.2, wspace=0.2)
        plt.show()

        download_choice = input("Deseja baixar o arquivo Excel com os IPs dos clusters? (S/N): ")
        if download_choice.upper() == 'S':
            root = tk.Tk()
            root.withdraw()
            file_path = filedialog.asksaveasfilename(defaultextension='.xlsx', filetypes=[('Excel files', '*.xlsx')], title='Salvar arquivo Excel dos IPs do Cluster')
            if file_path:
                with pd.ExcelWriter(file_path, engine='openpyxl') as writer:
                    for cluster in df['cluster'].unique():
                        cluster_data = df[df['cluster'] == cluster]
                        cluster_data_counts = cluster_data['IP'].value_counts().reset_index().rename(columns={'index': 'IP', 'IP': 'Quantidade'})
                        cluster_data_counts.to_excel(writer, sheet_name=f'Cluster {cluster}', index=False)
                        mean_feature_by_ip = cluster_data.groupby('IP')[selected_feature].mean().reset_index()
                        mean_feature_by_ip.rename(columns={selected_feature: f'Mean_{selected_feature}'}, inplace=True)
                        cluster_data_merged = pd.merge(cluster_data_counts, mean_feature_by_ip, on='IP', how='left')
                        cluster_data_merged.to_excel(writer, sheet_name=f'Cluster {cluster}', index=False)
                    print(f"Arquivo Excel com os IPs dos clusters, média da feature e quantidade de registros por IP foi salvo em {file_path}")
            else:
                print("Nenhum arquivo Excel foi salvo.")
        else:
            print("Nenhum arquivo Excel foi salvo.")

def plot_feature_selection(df, allowed_columns):
    df_filtered = df[allowed_columns]
    df_filtered = categorize_non_numeric_columns(df_filtered)
    selector_variance = VarianceThreshold()
    selector_variance.fit(df_filtered)
    variances = pd.Series(selector_variance.variances_, index=df_filtered.columns)
    plt.figure(figsize=(16, 8))
    plt.bar(variances.index, variances)
    plt.title('Variância das Features')
    plt.ylabel('Variância')
    plt.xticks(rotation=45, ha='right')
    for i, v in enumerate(variances):
        plt.text(i, v + 0.01, f'{v:.2f}', ha='center', va='bottom', fontsize=8)
    plt.subplots_adjust(top=0.93, bottom=0.32, left=0.125, right=0.9, hspace=0.2, wspace=0.2)
    plt.show()
    
    selector_kbest = SelectKBest(score_func=f_classif, k=5)
    selector_kbest.fit(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
    kbest_features = df_filtered.drop('score_average_Mobat', axis=1).columns[selector_kbest.get_support()]
    plt.figure(figsize=(16, 8)) 
    plt.bar(kbest_features, selector_kbest.scores_[selector_kbest.get_support()])
    plt.title('SelectKBest - Top 5 Features')
    plt.ylabel('Score')
    plt.xticks(rotation=45, ha='right')
    for i, v in enumerate(selector_kbest.scores_[selector_kbest.get_support()]):
        plt.text(i, v + 0.01, f'{v:.2f}', ha='center', va='bottom', fontsize=8)
    plt.subplots_adjust(top=0.945, bottom=0.245, left=0.105, right=0.9, hspace=0.2, wspace=0.2)
    plt.show()
    
    lasso = Lasso(alpha=0.1)
    lasso.fit(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
    lasso_coef = np.abs(lasso.coef_)
    plt.figure(figsize=(16, 8))  
    plt.bar(df_filtered.drop('score_average_Mobat', axis=1).columns, lasso_coef)
    plt.title("Lasso Coefficients")
    plt.ylabel("Coefficient Value")
    plt.xticks(rotation=45, ha='right')
    for i, v in enumerate(lasso_coef):
        plt.text(i, v + 0.001, f'{v:.2f}', ha='center', va='bottom', fontsize=8)
    plt.subplots_adjust(top=0.95, bottom=0.39, left=0.125, right=0.9, hspace=0.2, wspace=0.2)
    plt.show()
    
    mutual_info = mutual_info_regression(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
    plt.figure(figsize=(16, 8)) 
    plt.bar(df_filtered.drop('score_average_Mobat', axis=1).columns, mutual_info)
    plt.title('Mutual Information')
    plt.ylabel('Score')
    plt.xticks(rotation=45, ha='right')
    for i, v in enumerate(mutual_info):
        plt.text(i, v + 0.01, f'{v:.2f}', ha='center', va='bottom', fontsize=8)
    plt.subplots_adjust(top=0.945, bottom=0.315, left=0.125, right=0.9, hspace=0.2, wspace=0.2)
    plt.show()
    
    plt.figure(figsize=(24, 16))  
    sns.heatmap(df_filtered.corr(), annot=False, cmap='coolwarm')
    plt.title('Matriz de Correlação')
    plt.subplots_adjust(top=0.945, bottom=0.39, left=0.17, right=1.0, hspace=0.2, wspace=0.2)
    plt.show()
    return kbest_features

def plot_feature_importance(df, allowed_columns, model_types=['GradientBoostingRegressor', 'RandomForestRegressor', 'ExtraTreesRegressor', 'AdaBoostRegressor', 'XGBRegressor', 'ElasticNet']):
    df_filtered = df[allowed_columns]
    df_filtered = categorize_non_numeric_columns(df_filtered)
    for model_type in model_types:
        if model_type == 'GradientBoostingRegressor':
            model = GradientBoostingRegressor()
        elif model_type == 'RandomForestRegressor':
            model = RandomForestRegressor()
        elif model_type == 'ExtraTreesRegressor':
            model = ExtraTreesRegressor()
        elif model_type == 'AdaBoostRegressor':
            model = AdaBoostRegressor()
        elif model_type == 'XGBRegressor':
            model = XGBRegressor()
        elif model_type == 'ElasticNet':
            model = ElasticNet()
        else:
            raise ValueError("Model type not supported. Please choose a supported model.")
        model.fit(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
        if hasattr(model, 'feature_importances_'):
            feature_importances = model.feature_importances_
        elif hasattr(model, 'coef_'):
            feature_importances = np.abs(model.coef_)
        else:
            raise ValueError("Model does not have attribute 'feature_importances_' or 'coef_'.")
        ordered_feature_importances = [feature_importances[i] for i, col in enumerate(allowed_columns) if col != 'score_average_Mobat']
        plt.figure(figsize=(16, 8))
        plt.bar([col for col in allowed_columns if col != 'score_average_Mobat'], ordered_feature_importances)
        plt.xlabel('Características')
        plt.ylabel('Importância')
        plt.title(f'Importância das características no modelo {model_type} para score_average_Mobat')
        plt.xticks(rotation=45, ha='right')
        for feature, importance in zip([col for col in allowed_columns if col != 'score_average_Mobat'], ordered_feature_importances):
            plt.text(feature, importance + 0.005, f'{importance:.2f}', ha='center', va='bottom', rotation=45, fontsize=8)
        plt.tight_layout()
        plt.show()
    return None

def plot_top_ips_score_average(df, num_ips):
    top_ips = df['IP'].value_counts().nlargest(num_ips).index
    ip_variations = []
    for ip in top_ips:
        ip_data = df[df['IP'] == ip]
        score_variation = ip_data['score_average_Mobat'].max() - ip_data['score_average_Mobat'].min()
        ip_variations.append((ip, score_variation))
    top_ips_sorted = [ip for ip, _ in sorted(ip_variations, key=lambda x: x[1], reverse=True)]
    fig, ax = plt.subplots(figsize=(17, 10))  
    x_ticks = range(len(top_ips_sorted))
    x_labels = ['' for _ in x_ticks]  
    for ip in top_ips_sorted:
        ip_data = df[df['IP'] == ip]
        ax.plot(ip_data['IP'], ip_data['score_average_Mobat'], label=f'Variação: {ip_data["score_average_Mobat"].max() - ip_data["score_average_Mobat"].min():.2f}', linewidth=4)
    ax.set_title('Comportamento dos IPs mais recorrentes em relação ao Score Average Mobat')
    ax.set_ylabel('Score Average Mobat')
    legend = ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=6)
    for text in legend.get_texts():
        text.set_fontsize('x-small')  
    ax.grid(True)
    ax.set_xticks(x_ticks)
    ax.set_xticklabels(x_labels, rotation=90)
    plt.subplots_adjust(top=0.92, bottom=0.3, left=0.1, right=0.9, hspace=0.2, wspace=0.2)  
    plt.show()
    salvar = input("Deseja salvar os dados dos IPs em um arquivo Excel? (s/n): ")
    if salvar.lower() == 's':
        download_top_ips_score_average(df, num_ips)

def download_top_ips_score_average(df, num_ips):
    top_ips = df['IP'].value_counts().nlargest(num_ips).index
    ip_data_list = []
    for ip in top_ips:
        ip_data = df[df['IP'] == ip]
        min_score = ip_data['score_average_Mobat'].min()
        max_score = ip_data['score_average_Mobat'].max()
        score_variation = max_score - min_score
        ip_data_list.append({'IP': ip, 'Quantidade': len(ip_data), 'Variação': score_variation, 'Mínimo': min_score, 'Máximo': max_score})
    df_ip_data = pd.DataFrame(ip_data_list)
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.asksaveasfilename(defaultextension='.xlsx', filetypes=[('Excel files', '*.xlsx')])
    if file_path:
        df_ip_data.to_excel(file_path, index=False)
        print(f'Arquivo salvo em: {file_path}')

def plot_show_results_table(df, allowed_columns):
    df = categorize_non_numeric_columns(df)
    X = df[allowed_columns]
    y = df['score_average_Mobat']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
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

    def save_to_excel():
        file_path = filedialog.asksaveasfilename(defaultextension='.xlsx', filetypes=[('Excel files', '*.xlsx')])
        if file_path:
            results_df.to_excel(file_path, index=False)
            messagebox.showinfo('Info', 'File saved successfully.')

    def show_results():
        root = tk.Tk()
        root.title('Results')
        root.geometry('800x600')
        table = ttk.Treeview(root)
        table['columns'] = ('Model', 'Selection Technique', 'MSE', 'Training Time')
        table.column('#0', width=0, stretch=tk.NO)
        table.column('Model', anchor=tk.W, width=200)
        table.column('Selection Technique', anchor=tk.W, width=200)
        table.column('MSE', anchor=tk.W, width=100)
        table.column('Training Time', anchor=tk.W, width=100)
        table.heading('#0', text='', anchor=tk.W)
        table.heading('Model', text='Model', anchor=tk.W)
        table.heading('Selection Technique', text='Selection Technique', anchor=tk.W)
        table.heading('MSE', text='MSE', anchor=tk.W)
        table.heading('Training Time', text='Training Time', anchor=tk.W)
        for index, row in results_df.iterrows():
            table.insert('', tk.END, text=index, values=(row['Model'], row['Selection Technique'], row['MSE'], row['Training Time']))
        table.pack(expand=tk.YES, fill=tk.BOTH)
        save_button = tk.Button(root, text='Save to Excel', command=save_to_excel)
        save_button.pack()
        root.mainloop()
    show_results()

def download_all_ip_data(df):
    df_filled = df.fillna('None')
    root = tk.Tk()
    root.withdraw()
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        file_name = filedialog.asksaveasfilename(title="Salvar como", defaultextension=".xlsx",
                                                 filetypes=[("Arquivos Excel", "*.xlsx")])
        if file_name:
            df_filled.to_excel(file_name, index=False)
            print(f"Todos os dados foram salvos no arquivo {file_name}")
        else:
            print("Nenhum nome de arquivo selecionado")
    else:
        print("Nenhuma pasta selecionada")

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

seasons_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), 'Seasons'))

csv_files = [
    os.path.join(seasons_folder, 'PrimeiroSemestre.xlsx'),
    os.path.join(seasons_folder, 'SegundoSemestre.xlsx'),
    os.path.join(seasons_folder, 'TerceiroSemestre.xlsx'),
    os.path.join(seasons_folder, 'Total.xlsx')
]

df1 = pd.read_excel(csv_files[0])
df2 = pd.read_excel(csv_files[1])
df3 = pd.read_excel(csv_files[2])
df4 = pd.read_excel(csv_files[3])

mean_values_df1 = {
    'abuseipdb_confidence_score': df1['abuseipdb_confidence_score'].mean(),
    'abuseipdb_total_reports': df1['abuseipdb_total_reports'].mean(),
    'abuseipdb_num_distinct_users': df1['abuseipdb_num_distinct_users'].mean(),
    'virustotal_reputation': df1['virustotal_reputation'].mean(),
    'harmless': df1['harmless'].mean(),
    'malicious': df1['malicious'].mean(),
    'suspicious': df1['suspicious'].mean(),
    'undetected': df1['undetected'].mean(),
    'IBM_score': df1['IBM_score'].mean(),
    'IBM_average history Score': df1['IBM_average history Score'].mean(),
    'IBM_most common score': df1['IBM_most common score'].mean(),
    'score_average_Mobat': df1['score_average_Mobat'].mean()
}

mean_values_df2 = {
    'abuseipdb_confidence_score': df2['abuseipdb_confidence_score'].mean(),
    'abuseipdb_total_reports': df2['abuseipdb_total_reports'].mean(),
    'abuseipdb_num_distinct_users': df2['abuseipdb_num_distinct_users'].mean(),
    'virustotal_reputation': df2['virustotal_reputation'].mean(),
    'harmless': df2['harmless'].mean(),
    'malicious': df2['malicious'].mean(),
    'suspicious': df2['suspicious'].mean(),
    'undetected': df2['undetected'].mean(),
    'IBM_score': df2['IBM_score'].mean(),
    'IBM_average history Score': df2['IBM_average history Score'].mean(),
    'IBM_most common score': df2['IBM_most common score'].mean(),
    'score_average_Mobat': df2['score_average_Mobat'].mean()
}

mean_values_df3 = {
    'abuseipdb_confidence_score': df3['abuseipdb_confidence_score'].mean(),
    'abuseipdb_total_reports': df3['abuseipdb_total_reports'].mean(),
    'abuseipdb_num_distinct_users': df3['abuseipdb_num_distinct_users'].mean(),
    'virustotal_reputation': df3['virustotal_reputation'].mean(),
    'harmless': df3['harmless'].mean(),
    'malicious': df3['malicious'].mean(),
    'suspicious': df3['suspicious'].mean(),
    'undetected': df3['undetected'].mean(),
    'IBM_score': df3['IBM_score'].mean(),
    'IBM_average history Score': df3['IBM_average history Score'].mean(),
    'IBM_most common score': df3['IBM_most common score'].mean(),
    'score_average_Mobat': df3['score_average_Mobat'].mean()
}

mean_values_df4 = {
    'abuseipdb_confidence_score': df4['abuseipdb_confidence_score'].mean(),
    'abuseipdb_total_reports': df4['abuseipdb_total_reports'].mean(),
    'abuseipdb_num_distinct_users': df4['abuseipdb_num_distinct_users'].mean(),
    'virustotal_reputation': df4['virustotal_reputation'].mean(),
    'harmless': df4['harmless'].mean(),
    'malicious': df4['malicious'].mean(),
    'suspicious': df4['suspicious'].mean(),
    'undetected': df4['undetected'].mean(),
    'IBM_score': df4['IBM_score'].mean(),
    'IBM_average history Score': df4['IBM_average history Score'].mean(),
    'IBM_most common score': df4['IBM_most common score'].mean(),
    'score_average_Mobat': df4['score_average_Mobat'].mean()
}

while True:
    print("Selecione a tabela que deseja visualizar:")
    print("1. Abril-Maio(2023)")
    print("2. Setembro-Novembro(2023)")
    print("3. Janeiro-Março(2024)")
    print("4. Total Coletado")
    print("5. Sair")

    table_choice = input("Digite o número correspondente à tabela que deseja visualizar: ")

    if table_choice == "1":
        df_selected = df1
        mean_values = mean_values_df1
    elif table_choice == "2":
        df_selected = df2
        mean_values = mean_values_df2
    elif table_choice == "3":
        df_selected = df3
        mean_values = mean_values_df3
    elif table_choice == "4":
        df_selected = df4
        mean_values = mean_values_df4
    elif table_choice == "5":
        print("Saindo do programa...")
        break
    else:
        print("Escolha inválida.")
        continue

    print("Selecione o tipo de visualização:")
    print("1. Gráficos de Comportamento")
    print("2. Mapeamento das features")
    print("3. Clusters")
    print("4. Seleção de Características")
    print("5. Importâncias para Machine Learning")
    print("6. Score Average Mobat dos IPs com maior variação")
    print("7. Reputação por País")
    print("8. Upload da Tabela dos Ips do período")
    print("9. HeatMap de Ocorrência dos Ips nos países")
    print("10. Tabela de Acurácia e Tempo de Treinamento dos Modelos")
    print("11. Gráfico de Dispersão")
    print("14. Sair")

    visualization_choice = input("Digite o número correspondente à visualização desejada: ")

    if visualization_choice == "1":
        ips = df_selected['IP'].apply(extract_ip).unique()
        
        print('IPs disponíveis:')
        for i, ip in enumerate(ips):
            print(f'{i+1}. {ip}')

        def is_valid_ip(ip_input, ips):
            return ip_input in ips

        ip_input = input('Digite o número correspondente ao IP que deseja visualizar ou "s" para sair: ')

        if ip_input.lower() == "s":
            print("Saindo para o menu principal...")
            continue

        while not is_valid_ip(ip_input, ips):
            print('IP inválido. Por favor, digite um IP válido ou "s" para sair.')
            ip_input = input('Digite o número correspondente ao IP que deseja visualizar ou "s" para sair: ')

        ip_escolhido = ip_input
        plot_ip_data(df_selected, ip_escolhido, mean_values)

    elif visualization_choice == "2":
        print("Visualização do mapeamento das features:")
        plot_feature_mapping(df_selected)

    elif visualization_choice == "3":
        plot_clusters(df_selected)
        plt.show()

    elif visualization_choice == "4":
        print("Visualização da Seleção de Características:")
        plot_feature_selection(df_selected, allowed_columns)
        plt.show()

    elif visualization_choice == "5":
        print("Visualização da Importância para Machine Learning:")
        plot_feature_importance(df_selected, allowed_columns)
        plt.show()

    elif visualization_choice == "6":
        num_ips = int(input("Quantidade de IPs que deseja visualizar: "))
        print("Visualização do Score Average Mobat dos IPs:")
        plot_top_ips_score_average(df_selected, num_ips)
        plt.show()

    elif visualization_choice == "7":
        print("Visualização da Reputação por País:")
        plot_country_score_average(df_selected)
        plt.show()

    elif visualization_choice == "8":
        print("Baixar dados dos Ips do período: ")
        download_all_ip_data(df_selected)

    elif visualization_choice == "9":
        print("Ocorrências por País:")
        plot_country_heatmap(df_selected)

    elif visualization_choice == "10":
        print("Tabela de MSE e Training Time:")
        plot_show_results_table(df_selected, allowed_columns)
        continue
        
    elif visualization_choice == "11":
        print("Gráfico de Dispersão:")
        plot_dispersion_ip_reports(df_selected, treat_all_as_string=True)  

    elif visualization_choice == "12":
        print("Saindo para o menu principal...")
        continue

    else:
        print("Escolha inválida.")
        continue