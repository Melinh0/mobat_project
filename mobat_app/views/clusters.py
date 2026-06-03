from django.shortcuts import render, redirect
from django.http import HttpResponse
import sqlite3
import pandas as pd
import io
import base64
from mobat_app.utils.ml_helpers import plot_clusters

def clusters(request):
    allowed_columns = [
        'abuseipdb_confidence_score', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
        'virustotal_reputation', 'harmless', 'malicious', 'suspicious', 'undetected',
        'IBM_score', 'IBM_average history Score', 'IBM_most common score', 'score_average_Mobat'
    ]
    graphic = None

    if request.method == 'POST':
        action = request.POST.get('action')
        feature = request.POST.get('feature')
        num_clusters_str = request.POST.get('clusters')
        table_name = request.session.get('table_name')
        db_path = request.session.get('db_path')

        if not db_path:
            return HttpResponse("Caminho do banco de dados não encontrado.", status=400)
        if feature not in allowed_columns:
            return HttpResponse("Feature não permitida.", status=400)

        num_clusters = int(num_clusters_str) if num_clusters_str else 1
        request.session['num_clusters'] = num_clusters

        conn = sqlite3.connect(str(db_path))
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

        graphic = plot_clusters(df, feature, num_clusters)
        request.session['graphic'] = graphic

        if action == 'Visualizar Clusters':
            context = {'graphic': graphic, 'allowed_columns': allowed_columns, 'num_clusters': num_clusters}
            return render(request, 'clusters.html', context)
        elif action == 'Baixar Gráfico':
            if graphic:
                with io.BytesIO(base64.b64decode(graphic)) as buffer:
                    buffer.seek(0)
                    response = HttpResponse(buffer.read(), content_type='image/png')
                    response['Content-Disposition'] = 'attachment; filename="clusters.png"'
                del request.session['graphic']
                return response

    return render(request, 'clusters.html', {'graphic': graphic, 'allowed_columns': allowed_columns})