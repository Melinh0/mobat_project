from django.shortcuts import render, redirect
from django.http import HttpResponse
import sqlite3

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