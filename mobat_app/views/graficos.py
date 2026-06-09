from django.shortcuts import render, redirect
from django.http import HttpResponse
import pandas as pd
import base64
from mobat_app.models import IPData
from mobat_app.utils.plot_helpers import (
    plot_ip_location, plot_ip_reports, plot_ip_score_average,
    plot_ip_last_report, plot_ip_time_period, plot_ibm_scores,
    plot_ip_virustotal_stats
)

def get_df_from_semester(semester):
    qs = IPData.objects.filter(semester=semester).values()
    df = pd.DataFrame.from_records(qs)
    if df.empty:
        return df
    return df

def get_available_ips(df):
    if df.empty:
        return []
    return df['IP'].unique().tolist()

def graficos_comportamento(request):
    table_name = request.session.get('table_name')
    if not table_name:
        return redirect('index')

    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        chart_type = request.POST.get('chart_type')
        action = request.POST.get('action')

        if not ip_address or not chart_type:
            return redirect('index')

        df = get_df_from_semester(table_name)
        if df.empty:
            return HttpResponse("Nenhum dado encontrado para este semestre.", status=404)

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

        ips = get_available_ips(df)
        return render(request, 'graficos_comportamento.html', {
            'graphic': graphic,
            'ip_list': ips,
            'ip_address': ip_address,
        })

    df = get_df_from_semester(table_name)
    ips = get_available_ips(df)
    return render(request, 'graficos_comportamento.html', {'ip_list': ips, 'ip_address': ''})