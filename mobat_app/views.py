from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpRequest
from django.conf import settings
import tempfile
from io import BytesIO
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
from typing import Any, List
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
    request.session['table_choice'] = table_choice

    table_name = None
    if table_choice == '1':
        table_name = 'PrimeiroSemestre'
    elif table_choice == '2':
        table_name = 'SegundoSemestre'
    elif table_choice == '3':
        table_name = 'TerceiroSemestre'
    elif table_choice == '4':
        table_name = 'Total'

    if table_name is not None:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
        context = {'data': data}

        request.session['table_name'] = table_name
        return render(request, 'visualizar_funcionalidades.html', context)
    else:
        return HttpResponse("Error: Invalid table choice")
    
def get_available_ips(df_selected):
    return df_selected['IP'].unique().tolist()

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
    plt.xticks(range(len(ip_data)), [str(i) for i in range(1, len(ip_data) + 1)], rotation=90)  
    plt.gca().xaxis.set_label_coords(0.5, -0.1)
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.205, right=0.96, hspace=0.2, wspace=0.2)
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')
    plt.close()
    return graphic

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
    plt.xticks(range(len(ip_data)), [str(i) for i in range(1, len(ip_data)+1)], rotation=90)  
    handles, labels = plt.gca().get_legend_handles_labels()
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='\nReports > MeanScore: Malicioso\nReports < MeanScore: Benigno')]
    plt.legend(handles=handles + extra_handles, loc='upper right')
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.205, right=0.96, hspace=0.2, wspace=0.2)
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')
    plt.close()
    return graphic

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
    plt.xticks(range(len(ip_data)), [str(i) for i in range(1, len(ip_data)+1)], rotation=90)  
    handles, labels = plt.gca().get_legend_handles_labels()
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='\nScore > MeanScore: Benigno\nScore < MeanScore: Malicioso')]
    plt.legend(handles=handles + extra_handles, loc='upper right')
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.08, right=0.855, hspace=0.2, wspace=0.2)
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')
    plt.close()
    return graphic

def plot_ip_last_report(df, ip):
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
    plt.ylabel('Timestamp (Local)')
    plt.xlabel('Registros ao longo do tempo')
    plt.legend()
    plt.grid(True)
    plt.gca().xaxis.grid(True, linestyle='--')
    plt.gca().xaxis.set_label_coords(0.5, -0.1)
    plt.xticks(range(len(ip_data)), [str(x) for x in range(1, len(ip_data)+1)], rotation=90)
    plt.yticks(ip_data['abuseipdb_last_reported_at'], ip_data['abuseipdb_last_reported_at'].apply(lambda x: str(x)))
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.18, right=0.9, hspace=0.2, wspace=0.2)
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')
    plt.close()
    return graphic

def plot_ip_time_period(df, ip):
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
    
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    
    graphic = base64.b64encode(image_png).decode('utf-8')
    plt.close()
    return graphic

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
    plt.xticks(range(len(ip_data)), [str(x) for x in range(1, len(ip_data)+1)], rotation=90)
    handles, labels = plt.gca().get_legend_handles_labels()
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='\nScore > MeanScore: Benigno\nScore < MeanScore: Malicioso')]
    plt.legend(handles=handles + extra_handles, loc='upper right')
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.18, right=0.9, hspace=0.2, wspace=0.2)
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')
    plt.close()
    return graphic

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
    plt.xticks(range(len(ip_data)), [str(x) for x in range(1, len(ip_data)+1)], rotation=90)
    handles, labels = plt.gca().get_legend_handles_labels()
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='\nScore > MeanScore: Benigno\nScore < MeanScore: Malicioso')]
    plt.legend(handles=handles + extra_handles, loc='upper right')
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.18, right=0.9, hspace=0.2, wspace=0.2)
    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')
    plt.close()
    return graphic

def graficos_comportamento(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        chart_type = request.POST.get('chart_type')

        if ip_address and chart_type:
            table_name = request.session.get('table_name')
            if table_name is None:
                return redirect('index')

            db_path = request.session.get('db_path')
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()

            data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
            columns = [
                'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 
                'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 
                'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 
                'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 
                'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn', 
                'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
            ]
            df_selected = pd.DataFrame(data, columns=columns)
            mean_values = df_selected.mean(numeric_only=True)

            if chart_type == 'location':
                graphic = plot_ip_location(df_selected, ip_address)
            elif chart_type == 'reports':
                graphic = plot_ip_reports(df_selected, ip_address, mean_values)
            elif chart_type == 'score_average':
                graphic = plot_ip_score_average(df_selected, ip_address, mean_values)
            elif chart_type == 'last_report':
                graphic = plot_ip_last_report(df_selected, ip_address)
            elif chart_type == 'time_period':
                graphic = plot_ip_time_period(df_selected, ip_address)
            elif chart_type == 'ibm_scores':
                graphic = plot_ibm_scores(df_selected, ip_address, mean_values)
            elif chart_type == 'virustotal_stats':
                graphic = plot_ip_virustotal_stats(df_selected, ip_address, mean_values)
            else:
                graphic = None

            if request.POST.get('action') == 'Baixar Gráfico' and graphic:
                image_data = base64.b64decode(graphic)
                response = HttpResponse(image_data, content_type='image/png')
                response['Content-Disposition'] = 'attachment; filename="grafico.png"'
                return response

            return render(request, 'graficos_comportamento.html', {
                'graphic': graphic,
                'ip_list': get_available_ips(df_selected),
                'ip_address': ip_address,
            })

    table_name = request.session.get('table_name')
    if table_name is None:
        return redirect('index')

    db_path = request.session.get('db_path')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
    df_selected = pd.DataFrame(data, columns=[
        'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 
        'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 
        'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 
        'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average history Score', 'IBM_most common score', 
        'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
    ])

    ips = get_available_ips(df_selected)

    return render(request, 'graficos_comportamento.html', {
        'ip_list': ips,
        'ip_address': '',
    })

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

            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temp_file:
                plt.savefig(temp_file.name)
                temp_file_path = temp_file.name

            plt.close()

            with open(temp_file_path, "rb") as f:
                data_uri = f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"

            os.remove(temp_file_path)

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

def clusters(request: HttpRequest) -> HttpResponse:
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
        'score_average_Mobat'
    ]

    graphic = None
    num_clusters = 1
    if request.method == 'POST':
        action = request.POST.get('action')
        feature = request.POST.get('feature')
        num_clusters_str = request.POST.get('clusters')
        if feature not in allowed_columns:
            return HttpResponse("Feature não permitida.", status=400)

        num_clusters = int(num_clusters_str) if num_clusters_str else 1

        request.session['num_clusters'] = num_clusters  # Store the number of clusters in session

        table_name = request.session.get('table_name')
        db_path = request.session.get('db_path')
        if not db_path:
            return HttpResponse("Caminho do banco de dados não encontrado.", status=400)

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute(f"SELECT * FROM {table_name}")
        data = cursor.fetchall()
        conn.close()

        df = pd.DataFrame(data, columns=[
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
        ])

        graphic = plot_clusters(df, feature, num_clusters)
        request.session['graphic'] = graphic  

        if action == 'Visualizar Clusters':
            context = {'graphic': graphic, 'allowed_columns': allowed_columns, 'num_clusters': num_clusters}
            return render(request, 'clusters.html', context)

        elif action == 'Baixar Gráfico':
            graphic = request.session.get('graphic')
            if graphic:
                with io.BytesIO(base64.b64decode(graphic)) as buffer:
                    buffer.seek(0)
                    temp_file_path = os.path.join(os.path.dirname(__file__), 'graphic.png')
                    with open(temp_file_path, "wb") as f:
                        f.write(buffer.read())
                with open(temp_file_path, "rb") as f:
                    response = HttpResponse(f.read(), content_type='image/png')
                    response['Content-Disposition'] = 'attachment; filename="clusters.png"'
                os.remove(temp_file_path)
                del request.session['graphic']
                return response

    return render(request, 'clusters.html', {'graphic': graphic, 'allowed_columns': allowed_columns, 'num_clusters': num_clusters})

def plot_clusters(df, selected_feature, num_clusters):
    X = df[[selected_feature]]
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
    plt.tight_layout()

    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')

    return graphic

def plot_feature_selection(df: pd.DataFrame, allowed_columns: List[str], technique: str) -> str:
    df_filtered = categorize_non_numeric_columns(df[allowed_columns])

    def plot_variance_threshold():
        selector_variance = VarianceThreshold()
        selector_variance.fit(df_filtered)
        variances = pd.Series(selector_variance.variances_, index=df_filtered.columns)
        plot_bar(variances, 'Variância das Features')

    def plot_select_kbest():
        selector_kbest = SelectKBest(score_func=f_classif, k=5)
        selector_kbest.fit(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
        kbest_features = df_filtered.drop('score_average_Mobat', axis=1).columns[selector_kbest.get_support()]
        plot_bar(selector_kbest.scores_[selector_kbest.get_support()], 'SelectKBest - Top 5 Features', list(kbest_features)) # type: ignore

    def plot_lasso():
        lasso = Lasso(alpha=0.1)
        lasso.fit(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
        lasso_coef = np.abs(lasso.coef_)
        plot_bar(lasso_coef, 'Lasso Coefficients', list(df_filtered.drop('score_average_Mobat', axis=1).columns))

    def plot_mutual_info():
        mutual_info_vals = mutual_info_regression(df_filtered.drop('score_average_Mobat', axis=1), df_filtered['score_average_Mobat'])
        plot_bar(mutual_info_vals, 'Mutual Information', list(df_filtered.drop('score_average_Mobat', axis=1).columns))

    def plot_correlation_matrix():
        plt.figure(figsize=(20, 10))
        sns.heatmap(df_filtered.corr(), annot=False, cmap='coolwarm')
        plt.title('Matriz de Correlação')
        plt.subplots_adjust(top=0.945, bottom=0.5, left=0.125, right=0.9, hspace=0.2, wspace=0.2)

    def plot_bar(data: Any, title: str, xlabels: List[str] = None): # type: ignore
        if isinstance(data, np.ndarray):
            data = pd.Series(data, index=xlabels)
        plt.figure(figsize=(12, 6))
        plt.bar(data.index, data)
        plt.title(title)
        plt.ylabel('Score')
        plt.xticks(rotation=45, ha='right')
        for i, v in enumerate(data):
            plt.text(i, v + 0.01, f'{v:.2f}', ha='center', va='bottom', fontsize=8)
        plt.subplots_adjust(top=0.945, bottom=0.315, left=0.15, right=0.9, hspace=0.2, wspace=0.2)

    if technique == 'variance_threshold':
        plot_variance_threshold()
    elif technique == 'select_kbest':
        plot_select_kbest()
    elif technique == 'lasso':
        plot_lasso()
    elif technique == 'mutual_info':
        plot_mutual_info()
    elif technique == 'correlation_matrix':
        plot_correlation_matrix()
    else:
        raise ValueError("Invalid technique")

    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    plt.close()
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')

    return graphic

def selecao_caracteristicas(request):
    graphic = None  
    if request.method == 'POST':
        technique = request.POST.get('technique')
        action = request.POST.get('action')
        
        if technique == '' and action == 'Visualizar Seleção de Características':
            return HttpResponse("Por favor, selecione uma técnica válida.")
        
        table_name = request.session.get('table_name')
        db_path = request.session.get('db_path')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
        conn.close()

        df = pd.DataFrame(data, columns=[
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
        ])

        allowed_columns = [
            'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_total_reports',
            'abuseipdb_num_distinct_users', 'virustotal_reputation', 'harmless', 'malicious', 'suspicious',
            'undetected', 'IBM_score', 'IBM_average_history_Score', 'IBM_most_common_score',
            'score_average_Mobat'
        ]
        
        if action == 'Visualizar Seleção de Características':
            graphic = plot_feature_selection(df, allowed_columns, technique)

        if isinstance(graphic, str) and graphic.startswith("Nenhum dado"):
            return HttpResponse(graphic)

        if graphic:
            request.session['graphic_base64'] = graphic
    
    if request.method == 'GET' and request.GET.get('download') == 'true':
        graphic_base64 = request.session.get('graphic_base64')
        if graphic_base64:
            img_data = base64.b64decode(graphic_base64)
            response = HttpResponse(img_data, content_type='image/png')
            response['Content-Disposition'] = 'attachment; filename="graphic.png"'
            return response

    return render(request, 'selecao_caracteristicas.html', {'graphic': request.session.get('graphic_base64')})

def plot_feature_importance(df: pd.DataFrame, allowed_columns: list, model_type: str) -> str:
    df_filtered = df[allowed_columns]
    df_filtered = categorize_non_numeric_columns(df_filtered)
    
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
        feature_importances = model.feature_importances_  # type: ignore
    elif hasattr(model, 'coef_'):
        feature_importances = np.abs(model.coef_)  # type: ignore
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
    
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    
    graphic = base64.b64encode(image_png).decode('utf-8')
    return graphic

def importancias_ml(request):
    if request.method == 'POST':
        action = request.POST.get('action')
        model_type = request.POST.get('model_type')
        table_name = request.session.get('table_name')
        db_path = request.session.get('db_path')
        if not db_path:
            return HttpResponse("Caminho do banco de dados não encontrado.", status=400)
        
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
        conn.close()

        df = pd.DataFrame(data, columns=[
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
        ])

        allowed_columns = [
            'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_total_reports',
            'abuseipdb_num_distinct_users', 'virustotal_reputation', 'harmless', 'malicious', 'suspicious',
            'undetected', 'IBM_score', 'IBM_average_history_Score', 'IBM_most_common_score',
            'score_average_Mobat'
        ]

        if action == 'Visualizar Gráfico de Importância':
            graphic = plot_feature_importance(df, allowed_columns, model_type)
            request.session['graphic'] = graphic  
            context = {'graphic': graphic}
            return render(request, 'importancias_ml.html', context)

        elif action == 'Baixar Gráfico':
            graphic = request.session.get('graphic')
            if graphic:
                with BytesIO(base64.b64decode(graphic)) as buffer:
                    buffer.seek(0)
                    temp_file_path = os.path.join(os.path.dirname(__file__), 'graphic.png')
                    with open(temp_file_path, "wb") as f:
                        f.write(buffer.read())
                with open(temp_file_path, "rb") as f:
                    response = HttpResponse(f.read(), content_type='image/png')
                    response['Content-Disposition'] = 'attachment; filename="importancias_ml.png"'
                os.remove(temp_file_path)
                del request.session['graphic']
                return response

    return render(request, 'importancias_ml.html')

def plot_top_ips_score_average(df, num_ips, top=0.92, bottom=0.3):
    top_ips = df['IP'].value_counts().nlargest(num_ips).index
    ip_variations = []
    for ip in top_ips:
        ip_data = df[df['IP'] == ip]
        score_variation = ip_data['score_average_Mobat'].max() - ip_data['score_average_Mobat'].min()
        ip_variations.append((ip, score_variation))
    top_ips_sorted = [ip for ip, _ in sorted(ip_variations, key=lambda x: x[1], reverse=True)]

    fig, ax = plt.subplots(figsize=(17, 6))  
    x_ticks = range(len(top_ips_sorted))
    x_labels = top_ips_sorted  

    for ip in top_ips_sorted:
        ip_data = df[df['IP'] == ip]
        ax.plot(ip_data['IP'], ip_data['score_average_Mobat'], label=f'{ip}: Variação {ip_data["score_average_Mobat"].max() - ip_data["score_average_Mobat"].min():.2f}', linewidth=4)

    ax.set_title('Comportamento dos IPs mais recorrentes em relação ao Score Average Mobat')
    ax.set_ylabel('Score Average Mobat')
    legend = ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=6)
    for text in legend.get_texts():
        text.set_fontsize('x-small')  

    ax.grid(True)
    ax.set_xticks(x_ticks)
    ax.set_xticklabels([''] * len(x_labels), rotation=90, fontsize='small') 
    plt.subplots_adjust(top=top, bottom=bottom, left=0.1, right=0.95, hspace=0.2, wspace=0.2)  

    buffer = BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    plt.close()
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')

    return graphic

def score_average_mobat(request):
    if request.method == 'POST':
        num_ips = int(request.POST.get('num_ips', 1))
        top = float(request.POST.get('top', 0.92))
        bottom = float(request.POST.get('bottom', 0.3))
        table_name = request.session.get('table_name')
        db_path = request.session.get('db_path')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
        conn.close()

        df = pd.DataFrame(data, columns=[
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
        ])

        graphic = plot_top_ips_score_average(df, num_ips, top=top, bottom=bottom)
        request.session['graphic'] = graphic

    elif request.method == 'GET' and 'download' in request.GET:
        graphic = request.session.get('graphic')
        if graphic:
            with BytesIO(base64.b64decode(graphic)) as buffer:
                buffer.seek(0)
                response = HttpResponse(buffer.read(), content_type='image/png')
                response['Content-Disposition'] = 'attachment; filename="score_average_mobat.png"'
            del request.session['graphic']
            return response
        return HttpResponse("Gráfico não encontrado.", status=400)

    return render(request, 'score_average_mobat.html', {'graphic': request.session.get('graphic')})

def plot_country_score_average(df, country=None):
    country_names = {
        'US': 'Estados Unidos', 'CN': 'China', 'SG': 'Singapura', 'DE': 'Alemanha', 'VN': 'Vietnã',
        'KR': 'Coreia do Sul', 'IN': 'Índia', 'RU': 'Rússia', 'LT': 'Lituânia', 'TW': 'Taiwan',
        'GB': 'Reino Unido', 'JP': 'Japão', 'IR': 'Irã', 'BR': 'Brasil', 'AR': 'Argentina',
        'NL': 'Holanda', 'TH': 'Tailândia', 'CA': 'Canadá', 'PK': 'Paquistão', 'ID': 'Indonésia',
        'ET': 'Etiópia', 'FR': 'França', 'BG': 'Bulgária', 'PA': 'Panamá', 'SA': 'Arábia Saudita',
        'BD': 'Bangladesh', 'HK': 'Hong Kong', 'MA': 'Marrocos', 'EG': 'Egito', 'UA': 'Ucrânia',
        'MX': 'México', 'UZ': 'Uzbequistão', 'ES': 'Espanha', 'AU': 'Austrália', 'CO': 'Colômbia',
        'KZ': 'Cazaquistão', 'EC': 'Equador', 'BZ': 'Belize', 'SN': 'Senegal', 'None': 'None',
        'IE': 'Irlanda', 'FI': 'Finlândia', 'ZA': 'África do Sul', 'IT': 'Itália', 'PH': 'Filipinas',
        'CR': 'Costa Rica', 'CH': 'Suíça'
    }

    if country:
        df = df[df['abuseipdb_country_code'] == country]

    if df.empty:
        return "Nenhum dado encontrado para o país selecionado." if country else "Nenhum dado disponível."

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
    
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    
    graphic = base64.b64encode(image_png)
    graphic = graphic.decode('utf-8')
    
    return graphic

def reputacao_pais(request):
    graphic = None  
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

        df = pd.DataFrame(data, columns=[
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
        ])

        if action == 'Visualizar o País Escolhido':
            graphic = plot_country_score_average(df, country)
        elif action == 'Visualizar Todos os Países':
            graphic = plot_country_score_average(df)
        
        if isinstance(graphic, str) and graphic.startswith("Nenhum dado"):
            return HttpResponse(graphic)
        
        request.session['graphic'] = graphic

    elif request.method == 'GET' and 'download' in request.GET:
        graphic = request.session.get('graphic')
        if graphic:
            with io.BytesIO(base64.b64decode(graphic)) as buffer:
                buffer.seek(0)
                temp_file_path = os.path.join(os.path.dirname(__file__), 'graphic.png')
                with open(temp_file_path, "wb") as f:
                    f.write(buffer.read())
            with open(temp_file_path, "rb") as f:
                response = HttpResponse(f.read(), content_type='image/png')
                response['Content-Disposition'] = 'attachment; filename="graphic.png"'
            os.remove(temp_file_path)
            return response

    return render(request, 'reputacao_pais.html', {'graphic': graphic})

def upload_tabela_ips(request):
    if request.method == 'POST':
        file_type = request.POST.get('file_type')

        if file_type in ['excel', 'csv', 'parquet', 'json', 'orc', 'avro', 'xml']:
            table_name = request.session.get('table_name')
            db_path = settings.BASE_DIR / request.session.get('db_path')

            conn = sqlite3.connect(db_path)
            df = pd.read_sql_query(f"SELECT * FROM {table_name}", conn)

            return download_all_ip_data(df, file_type)

    return render(request, 'upload_tabela_ips.html')

def clean_xml_tag(tag):
    tag = tag.replace(' ', '_')  
    tag = ''.join(c for c in tag if c.isalnum() or c in ['_', '-'])  
    return tag

def download_all_ip_data(df, file_type):
    df_filled = df.fillna('None')
    if file_type == 'excel':
        response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.xlsx'
        df_filled.to_excel(response, index=False)
    elif file_type == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.csv'
        df_filled.to_csv(response, index=False)
    elif file_type == 'parquet':
        response = HttpResponse(content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.parquet'
        df_filled.to_parquet(response, index=False)
    elif file_type == 'json':
        response = HttpResponse(content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.json'
        df_filled.to_json(response, orient='records')
    elif file_type == 'orc':
        response = HttpResponse(content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.orc'
        df_filled.to_orc(response, index=False)
    elif file_type == 'avro':
        response = HttpResponse(content_type='application/octet-stream')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.avro'
        df_filled.to_avro(response, index=False)
    elif file_type == 'xml':
        response = HttpResponse(content_type='application/xml')
        response['Content-Disposition'] = 'attachment; filename=tabela_ips.xml'
        df_filled.columns = [clean_xml_tag(col) for col in df_filled.columns]
        xml_data = df_filled.to_xml(index=False)
        response.write(xml_data)
    else:
        return HttpResponse("Tipo de arquivo inválido")

    return response

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
            df = pd.DataFrame(data, columns=['IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code', 'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users', 'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry', 'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score', 'IBM_average_history_Score', 'IBM_most_common_score', 'virustotal_asn', 'SHODAN_asn', 'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'])

            df_selected = df.dropna(subset=["abuseipdb_country_code"])
            serie_country_counts = df_selected["abuseipdb_country_code"].value_counts()
            min_count, max_count = serie_country_counts.min(), serie_country_counts.max()
            df_country_counts = serie_country_counts.rename_axis("country_code").reset_index(name="count")
            df_country_counts["country_code"] = df_country_counts["country_code"].apply(alpha2_to_alpha3)
            df_country_counts.dropna(subset=["country_code"], inplace=True)

            SHAPEFILE = "mobat_app/shapefiles/ne_10m_admin_0_countries.shp"
            geo_df = gpd.read_file(SHAPEFILE)[["ADMIN", "ADM0_A3", "geometry"]]
            geo_df.columns = ["country", "country_code", "geometry"]
            geo_df = geo_df.drop(geo_df.loc[geo_df["country"] == "Antarctica"].index)
            geo_df = geo_df.merge(df_country_counts, on="country_code", how="left")
            geo_df["count"] = geo_df["count"].fillna(0)
            geo_df["normalized_count"] = (geo_df["count"] - min_count) / (max_count - min_count)

            fig, ax = plt.subplots(figsize=(20, 10))
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
            plt.subplots_adjust(top=0.9, bottom=0.08, left=0.03, right=0.95, hspace=0.2, wspace=0.2)

            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temp_file:
                plt.savefig(temp_file.name)
                temp_file_path = temp_file.name

            conn.close()

            with open(temp_file_path, "rb") as f:
                data_uri = f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"

            context = {'image_path': data_uri, 'temp_file_path': temp_file_path}
            return render(request, 'heatmap_ips.html', context)

        elif action == 'Baixar HeatMap':
            temp_file_path = request.POST.get('temp_file_path', '')
            if temp_file_path:
                with open(temp_file_path, "rb") as f:
                    response = HttpResponse(f.read(), content_type='image/png')
                    response['Content-Disposition'] = 'attachment; filename="heatmap.png"'
                os.remove(temp_file_path)
                return response

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
            request.session['results_df'] = results_df.to_json() 
            request.session['table_generated'] = True 

            return render(request, 'tabela_acuracia.html', {
                'results_html': results_html,
                'table_generated': True 
            })

        elif action == 'Baixar Tabela':
            results_df_json = request.session.get('results_df')
            if results_df_json:
                results_df = pd.read_json(results_df_json)
                response = HttpResponse(content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')
                response['Content-Disposition'] = 'attachment; filename="tabela_acuracia.xlsx"'
                results_df.to_excel(response, index=False)
                return response

    return render(request, 'tabela_acuracia.html', {
        'results_html': request.session.get('results_html'),
        'table_generated': request.session.get('table_generated', False) 
    })

def categorize_non_numeric_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in df.select_dtypes(include=['object', 'category']).columns:
        if col != 'IP':
            df[col] = df[col].astype('category').cat.codes
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

        plt.figure(figsize=(12, 7))
        plt.scatter(x_data, y_data, s=y_weights*10, color='blue', alpha=0.6)
        plt.title(f'Dispersão: {x_axis} vs {y_axis}')
        plt.xlabel(x_axis)
        plt.ylabel(y_axis)
        plt.grid(True)
        plt.subplots_adjust(top=0.92, bottom=0.08, left=0.1, right=0.95, hspace=0.2, wspace=0.2)

        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as temp_file:
            plt.savefig(temp_file.name)
            temp_file_path = temp_file.name

        plt.close()

        with open(temp_file_path, "rb") as f:
            data_uri = f"data:image/png;base64,{base64.b64encode(f.read()).decode()}"

        request.session['temp_file_path'] = temp_file_path

        return render(request, 'grafico_dispersao.html', {'plot': data_uri})

    if 'download' in request.GET:
        temp_file_path = request.session.get('temp_file_path', '')
        if temp_file_path and os.path.exists(temp_file_path):
            with open(temp_file_path, "rb") as f:
                response = HttpResponse(f.read(), content_type='image/png')
                response['Content-Disposition'] = 'attachment; filename="grafico_dispersao.png"'
            os.remove(temp_file_path)
            return response

    return render(request, 'grafico_dispersao.html')