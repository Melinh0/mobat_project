from django.shortcuts import render, redirect
from django.http import HttpResponse
import pandas as pd
import io
import base64
from mobat_app.models import IPData
from mobat_app.utils.plot_helpers import plot_top_ips_score_average

def score_average_mobat(request):
    table_name = request.session.get('table_name')
    if not table_name:
        return redirect('index')

    if request.method == 'POST':
        num_ips = int(request.POST.get('num_ips', 1))
        top = float(request.POST.get('top', 0.92))
        bottom = float(request.POST.get('bottom', 0.3))

        qs = IPData.objects.filter(semester=table_name).values()
        df = pd.DataFrame.from_records(qs)

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