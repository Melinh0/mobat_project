from django.shortcuts import render, redirect
from django.http import HttpResponse
from mobat_app.models import IPData

def visualizar_funcionalidades(request):
    table_choice = request.GET.get('table_choice')
    semester_map = {
        '1': 'PrimeiroSemestre',
        '2': 'SegundoSemestre',
        '3': 'TerceiroSemestre',
        '4': 'Total',
    }
    table_name = semester_map.get(table_choice)
    if not table_name:
        return HttpResponse("Error: Invalid table choice")

    request.session['table_choice'] = table_choice
    request.session['table_name'] = table_name

    data = IPData.objects.filter(semester=table_name).values()
    context = {'data': list(data)}
    return render(request, 'visualizar_funcionalidades.html', context)