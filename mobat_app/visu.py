import sqlite3

conn = sqlite3.connect('/home/yago/mobat_project/mobat_app/Seasons/SegundoSemestre.sqlite')
cursor = conn.cursor()
cursor.execute("SELECT * FROM SegundoSemestre")
colunas = [descricao[0] for descricao in cursor.description]
resultados = cursor.fetchall()
conn.close()
print("Nomes das colunas:", colunas)
for linha in resultados:
    print(dict(zip(colunas, linha)))

