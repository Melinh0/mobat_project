from django.shortcuts import render, redirect
from django.http import HttpResponse
import pandas as pd
import io
import base64
from mobat_app.models import IPData
from mobat_app.utils.ml_helpers import plot_clusters

def clusters(request):
    allowed_columns = [
        'abuseipdb_confidence_score', 'abuseipdb_total_reports', 'abuseipdb_num_distinct_users',
        'virustotal_reputation', 'harmless', 'malicious', 'suspicious', 'undetected',
        'IBM_score', 'IBM_average_history_Score', 'IBM_most_common_score', 'score_average_Mobat'
    ]
    graphic = None

    table_name = request.session.get('table_name')
    if not table_name:
        return redirect('index')

    if request.method == 'POST':
        action = request.POST.get('action')
        feature = request.POST.get('feature')
        num_clusters_str = request.POST.get('clusters')

        if feature not in allowed_columns:
            return HttpResponse("Feature não permitida.", status=400)

        num_clusters = int(num_clusters_str) if num_clusters_str else 1
        request.session['num_clusters'] = num_clusters

        qs = IPData.objects.filter(semester=table_name).values()
        df = pd.DataFrame.from_records(qs)

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