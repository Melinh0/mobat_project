from django.shortcuts import render, redirect
from django.http import HttpResponse
import sqlite3
import pandas as pd
import base64
from mobat_app.utils.plot_helpers import (
    plot_ip_location, plot_ip_reports, plot_ip_score_average,
    plot_ip_last_report, plot_ip_time_period, plot_ibm_scores,
    plot_ip_virustotal_stats
)

def graficos_comportamento(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        chart_type = request.POST.get('chart_type')
        action = request.POST.get('action')

        if not ip_address or not chart_type:
            return redirect('index')

        table_name = request.session.get('table_name')
        db_path = request.session.get('db_path')
        if not table_name or not db_path:
            return redirect('index')

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        columns = [
            'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
            'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
            'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
            'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
            'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn',
            'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
        ]
        data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
        conn.close()

        df = pd.DataFrame(data, columns=columns)
        mean_values = df.mean(numeric_only=True)

        graphic = None
        if chart_type == 'location':
            graphic = plot_ip_location(df, ip_address)
        elif chart_type == 'reports':
            graphic = plot_ip_reports(df, ip_address, mean_values)
        elif chart_type == 'score_average':
            graphic = plot_ip_score_average(df, ip_address, mean_values)
        elif chart_type == 'last_report':
            graphic = plot_ip_last_report(df, ip_address)
        elif chart_type == 'time_period':
            graphic = plot_ip_time_period(df, ip_address)
        elif chart_type == 'ibm_scores':
            graphic = plot_ibm_scores(df, ip_address, mean_values)
        elif chart_type == 'virustotal_stats':
            graphic = plot_ip_virustotal_stats(df, ip_address, mean_values)

        if action == 'Baixar Gráfico' and graphic:
            image_data = base64.b64decode(graphic)
            response = HttpResponse(image_data, content_type='image/png')
            response['Content-Disposition'] = 'attachment; filename="grafico.png"'
            return response

        ips = df['IP'].unique().tolist()
        return render(request, 'graficos_comportamento.html', {
            'graphic': graphic,
            'ip_list': ips,
            'ip_address': ip_address,
        })

    table_name = request.session.get('table_name')
    if not table_name:
        return redirect('index')
    db_path = request.session.get('db_path')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    columns = [
        'IP', 'abuseipdb_is_whitelisted', 'abuseipdb_confidence_score', 'abuseipdb_country_code',
        'abuseipdb_isp', 'abuseipdb_domain', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
        'abuseipdb_last_reported_at', 'virustotal_reputation', 'virustotal_regional_internet_registry',
        'virustotal_as_owner', 'harmless', 'malicious', 'suspicious', 'undetected', 'IBM_score',
        'IBM_average history Score', 'IBM_most common score', 'virustotal_asn', 'SHODAN_asn',
        'SHODAN_isp', 'ALIENVAULT_reputation', 'ALIENVAULT_asn', 'score_average_Mobat'
    ]
    data = cursor.execute(f"SELECT * FROM {table_name}").fetchall()
    conn.close()
    df = pd.DataFrame(data, columns=columns)
    ips = df['IP'].unique().tolist()
    return render(request, 'graficos_comportamento.html', {'ip_list': ips, 'ip_address': ''})