import pandas as pd
import sqlite3

# Carregar o arquivo CSV em um DataFrame
df = pd.read_csv('/home/yago/mobat_project/Total - Total.csv.csv')

# Conectar ao banco de dados SQLite
conn = sqlite3.connect('/home/yago/mobat_project/mobat_app/Seasons/Total.sqlite')

# Salvar o DataFrame como uma tabela no banco de dados SQLite
df.to_sql('Total', conn, if_exists='replace', index=False)

# Fechar a conexão com o banco de dados
conn.close()
