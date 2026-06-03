import io
import base64
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import pytz
from matplotlib.lines import Line2D

def plot_ip_location(df, ip):
    ip_data = df[df['IP'] == ip]
    country_names = {
        'US': 'Estados Unidos', 'CN': 'China', 'SG': 'Singapura', 'DE': 'Alemanha',
        'VN': 'Vietnã', 'KR': 'Coreia do Sul', 'IN': 'Índia', 'RU': 'Rússia',
        'LT': 'Lituânia', 'TW': 'Taiwan', 'GB': 'Reino Unido', 'JP': 'Japão',
        'IR': 'Irã', 'BR': 'Brasil', 'AR': 'Argentina', 'NL': 'Holanda',
        'TH': 'Tailândia', 'CA': 'Canadá', 'PK': 'Paquistão', 'ID': 'Indonésia',
        'ET': 'Etiópia', 'FR': 'França', 'BG': 'Bulgária', 'PA': 'Panamá',
        'SA': 'Arábia Saudita', 'BD': 'Bangladesh', 'HK': 'Hong Kong', 'MA': 'Marrocos',
        'EG': 'Egito', 'UA': 'Ucrânia', 'MX': 'México', 'UZ': 'Uzbequistão',
        'ES': 'Espanha', 'AU': 'Austrália', 'CO': 'Colômbia', 'KZ': 'Cazaquistão',
        'EC': 'Equador', 'BZ': 'Belize', 'SN': 'Senegal', 'None': 'None',
        'IE': 'Irlanda', 'FI': 'Finlândia', 'ZA': 'África do Sul', 'IT': 'Itália',
        'PH': 'Filipinas', 'CR': 'Costa Rica', 'CH': 'Suíça'
    }
    plt.figure(figsize=(16, 8))
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
    plt.xticks(range(len(ip_data)), [str(i) for i in range(1, len(ip_data)+1)], rotation=90)
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.205, right=0.96, hspace=0.2, wspace=0.2)
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
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
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
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
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()
    return graphic

def plot_ip_last_report(df, ip):
    fusos_paises = {
        'CN': 'Asia/Shanghai', 'US': 'America/New_York', 'SG': 'Asia/Singapore',
        'IN': 'Asia/Kolkata', 'LT': 'Europe/Vilnius', 'DE': 'Europe/Berlin',
        'GB': 'Europe/London', 'KR': 'Asia/Seoul', 'RU': 'Europe/Moscow',
        'VN': 'Asia/Ho_Chi_Minh', 'CA': 'America/Toronto', 'TW': 'Asia/Taipei',
        'JP': 'Asia/Tokyo', 'BR': 'America/Sao_Paulo', 'NL': 'Europe/Amsterdam',
        'TH': 'Asia/Bangkok', 'MX': 'America/Mexico_City', 'UZ': 'Asia/Tashkent',
        'UA': 'Europe/Kiev', 'BD': 'Asia/Dhaka', 'AR': 'America/Argentina/Buenos_Aires',
        'IR': 'Asia/Tehran', 'ET': 'Africa/Addis_Ababa', 'BG': 'Europe/Sofia',
        'MA': 'Africa/Casablanca', 'EG': 'Africa/Cairo', 'ES': 'Europe/Madrid',
        'HK': 'Asia/Hong_Kong', 'ID': 'Asia/Jakarta', 'FR': 'Europe/Paris',
        'ZA': 'Africa/Johannesburg', 'PH': 'Asia/Manila', 'CH': 'Europe/Zurich',
        'IT': 'Europe/Rome', 'CR': 'America/Costa_Rica', 'IE': 'Europe/Dublin',
        'AT': 'Europe/Vienna', 'AU': 'Australia/Sydney', 'FI': 'Europe/Helsinki',
        'PK': 'Asia/Karachi', 'SA': 'Asia/Riyadh', 'PA': 'America/Panama',
        'KZ': 'Asia/Almaty', 'CO': 'America/Bogota', 'EC': 'America/Guayaquil',
        'SN': 'Africa/Dakar', 'BZ': 'America/Belize'
    }
    ip_data = df[df['IP'] == ip].copy()
    ip_data['abuseipdb_last_reported_at'] = pd.to_datetime(ip_data['abuseipdb_last_reported_at'], errors='coerce')
    ip_data = ip_data.sort_values(by='abuseipdb_last_reported_at')
    ip_data = ip_data[ip_data['abuseipdb_last_reported_at'].notna()]

    def convert_to_timezone(row):
        tz = fusos_paises.get(row['abuseipdb_country_code'])
        if tz:
            return row['abuseipdb_last_reported_at'].astimezone(pytz.timezone(tz))
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
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()
    return graphic

def plot_ip_time_period(df, ip):
    fusos_paises = {
        'CN': 'Asia/Shanghai', 'US': 'America/New_York', 'SG': 'Asia/Singapore',
        'IN': 'Asia/Kolkata', 'LT': 'Europe/Vilnius', 'DE': 'Europe/Berlin',
        'GB': 'Europe/London', 'KR': 'Asia/Seoul', 'RU': 'Europe/Moscow',
        'VN': 'Asia/Ho_Chi_Minh', 'CA': 'America/Toronto', 'TW': 'Asia/Taipei',
        'JP': 'Asia/Tokyo', 'BR': 'America/Sao_Paulo', 'NL': 'Europe/Amsterdam',
        'TH': 'Asia/Bangkok', 'MX': 'America/Mexico_City', 'UZ': 'Asia/Tashkent',
        'UA': 'Europe/Kiev', 'BD': 'Asia/Dhaka', 'AR': 'America/Argentina/Buenos_Aires',
        'IR': 'Asia/Tehran', 'ET': 'Africa/Addis_Ababa', 'BG': 'Europe/Sofia',
        'MA': 'Africa/Casablanca', 'EG': 'Africa/Cairo', 'ES': 'Europe/Madrid',
        'HK': 'Asia/Hong_Kong', 'ID': 'Asia/Jakarta', 'FR': 'Europe/Paris',
        'ZA': 'Africa/Johannesburg', 'PH': 'Asia/Manila', 'CH': 'Europe/Zurich',
        'IT': 'Europe/Rome', 'CR': 'America/Costa_Rica', 'IE': 'Europe/Dublin',
        'AT': 'Europe/Vienna', 'AU': 'Australia/Sydney', 'FI': 'Europe/Helsinki',
        'PK': 'Asia/Karachi', 'SA': 'Asia/Riyadh', 'PA': 'America/Panama',
        'KZ': 'Asia/Almaty', 'CO': 'America/Bogota', 'EC': 'America/Guayaquil',
        'SN': 'Africa/Dakar', 'BZ': 'America/Belize'
    }
    ip_data = df[df['IP'] == ip].copy()
    ip_data['abuseipdb_last_reported_at'] = pd.to_datetime(ip_data['abuseipdb_last_reported_at'], errors='coerce')
    ip_data = ip_data.sort_values(by='abuseipdb_last_reported_at')
    ip_data = ip_data[ip_data['abuseipdb_last_reported_at'].notna()]

    def convert_to_timezone(row):
        tz = fusos_paises.get(row['abuseipdb_country_code'])
        if tz:
            return row['abuseipdb_last_reported_at'].astimezone(pytz.timezone(tz))
        return row['abuseipdb_last_reported_at']

    ip_data['abuseipdb_last_reported_at'] = ip_data.apply(convert_to_timezone, axis=1)
    morning = ip_data[(ip_data['abuseipdb_last_reported_at'].dt.hour >= 5) & (ip_data['abuseipdb_last_reported_at'].dt.hour < 12)]
    afternoon = ip_data[(ip_data['abuseipdb_last_reported_at'].dt.hour >= 12) & (ip_data['abuseipdb_last_reported_at'].dt.hour < 18)]
    night = ip_data[(ip_data['abuseipdb_last_reported_at'].dt.hour >= 18) | (ip_data['abuseipdb_last_reported_at'].dt.hour < 5)]
    counts = [len(morning), len(afternoon), len(night)]
    plt.figure(figsize=(16, 8))
    plt.bar(['Manhã', 'Tarde', 'Noite'], counts, color=['skyblue', 'orange', 'green'])
    plt.title(f'Períodos do Dia com mais ocorrência de report do IP {ip}')
    plt.xlabel('Período do Dia')
    plt.ylabel('Ocorrências')
    extra_handles = [Line2D([0], [0], color='white', linewidth=0, marker='o', markersize=0, label='Manhã: 5h-12h\nTarde: 12h-18h\nNoite: 18h-5h')]
    plt.legend(handles=extra_handles, loc='lower right')
    plt.grid(axis='y')
    plt.subplots_adjust(top=0.88, bottom=0.11, left=0.18, right=0.9, hspace=0.2, wspace=0.2)
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
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
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
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
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
    plt.close()
    return graphic

def plot_top_ips_score_average(df, num_ips, top=0.92, bottom=0.3):
    df['score_average_Mobat'] = pd.to_numeric(df['score_average_Mobat'], errors='coerce')
    df = df.dropna(subset=['score_average_Mobat'])
    top_ips = df['IP'].value_counts().nlargest(num_ips).index
    ip_variations = [(ip, df[df['IP'] == ip]['score_average_Mobat'].max() - df[df['IP'] == ip]['score_average_Mobat'].min()) for ip in top_ips]
    top_ips_sorted = [ip for ip, _ in sorted(ip_variations, key=lambda x: x[1], reverse=True)]
    fig, ax = plt.subplots(figsize=(17, 6))
    for ip in top_ips_sorted:
        ip_data = df[df['IP'] == ip]
        ax.plot(ip_data['IP'], ip_data['score_average_Mobat'], label=f'{ip}: Variação {ip_data["score_average_Mobat"].max() - ip_data["score_average_Mobat"].min():.2f}', linewidth=4)
    ax.set_title('Comportamento dos IPs mais recorrentes em relação ao Score Average Mobat')
    ax.set_ylabel('Score Average Mobat')
    legend = ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.05), fancybox=True, shadow=True, ncol=6)
    for text in legend.get_texts():
        text.set_fontsize('x-small')
    ax.grid(True)
    ax.set_xticks(range(len(top_ips_sorted)))
    ax.set_xticklabels([''] * len(top_ips_sorted), rotation=90, fontsize='small')
    plt.subplots_adjust(top=top, bottom=bottom, left=0.1, right=0.95, hspace=0.2, wspace=0.2)
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=75)
    plt.close()
    buffer.seek(0)
    graphic = base64.b64encode(buffer.getvalue()).decode('utf-8')
    return graphic

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
    df = df.copy()
    df['score_average_Mobat'] = pd.to_numeric(df['score_average_Mobat'], errors='coerce')
    df = df.dropna(subset=['score_average_Mobat'])
    if df.empty:
        return "Nenhum dado numérico disponível após limpeza."
    global_avg_scores = df.groupby('abuseipdb_country_code')['score_average_Mobat'].mean().sort_values(ascending=False)
    global_avg_scores.index = global_avg_scores.index.map(country_names)
    mean_of_means = global_avg_scores.mean()
    if country:
        df = df[df['abuseipdb_country_code'] == country]
        if df.empty:
            return "Nenhum dado encontrado para o país selecionado."
    country_avg_scores = df.groupby('abuseipdb_country_code')['score_average_Mobat'].mean().sort_values(ascending=False)
    country_avg_scores.index = country_avg_scores.index.map(country_names)
    country_avg_scores = country_avg_scores[~country_avg_scores.index.isna()]
    plt.figure(figsize=(16, 8))
    bars = plt.bar(country_avg_scores.index.astype(str), country_avg_scores.values, color='skyblue')
    plt.axhline(mean_of_means, linestyle='--', color='red', label=f'Média das médias global: {mean_of_means:.2f}')
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
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png')
    plt.close()
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    graphic = base64.b64encode(image_png).decode('utf-8')
    return graphic