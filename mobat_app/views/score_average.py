from django.shortcuts import render, redirect
from django.http import HttpResponse
import sqlite3
import pandas as pd
import io
import base64
from mobat_app.utils.plot_helpers import plot_top_ips_score_average

def score_average_mobat(request):
    if request.method == 'POST':
        num_ips = int(request.POST.get('num_ips', 1))
        top = float(request.POST.get('top', 0.92))
        bottom = float(request.POST.get('bottom', 0.3))
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

        graphic = plot_top_ips_score_average(df, num_ips, top=top, bottom=bottom)
        request.session['graphic'] = graphic

    elif request.method == 'GET' and 'download' in request.GET:
        graphic = request.session.get('graphic')
        if graphic:
            with io.BytesIO(base64.b64decode(graphic)) as buffer:
                buffer.seek(0)
                response = HttpResponse(buffer.read(), content_type='image/png')
                response['Content-Disposition'] = 'attachment; filename="score_average_mobat.png"'
            del request.session['graphic']
            return response
        return HttpResponse("Gráfico não encontrado.", status=400)

    return render(request, 'score_average_mobat.html', {'graphic': request.session.get('graphic')})