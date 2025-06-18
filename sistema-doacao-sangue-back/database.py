import sqlite3
from sqlite3 import Error
import sys

def get_db_connection():
    """Cria e retorna uma conexão com o banco de dados SQLite."""
    try:
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row
        return conn
    except Error as e:
        print(f"❌ Erro ao conectar ao SQLite: {e}", file=sys.stderr)
        return None

def init_db(app):
    """
    Inicializa o banco de dados.
    Cria a tabela 'polos' com campos de endereço estruturados se ela não existir.
    Esta função deve ser chamada no contexto da aplicação Flask.
    """
    with app.app_context():
        conn = get_db_connection()
        if conn is None:
            sys.exit(1)

        try:
            cursor = conn.cursor()
            
            print("🔧 Verificando e criando a tabela 'polos' com endereço estruturado...")

            cursor.execute('''
            CREATE TABLE IF NOT EXISTS polos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                
                -- Informações de Identificação do Polo
                nome_polo TEXT NOT NULL UNIQUE,
                telefone TEXT,
                
                -- Campos de Endereço Estruturado
                pais TEXT NOT NULL,
                estado TEXT NOT NULL,
                cidade TEXT NOT NULL,
                cep TEXT NOT NULL,
                endereco TEXT NOT NULL,
                numero TEXT,
                complemento TEXT, -- Campo adicional útil
                
                -- Informações de Login e Acesso
                email TEXT NOT NULL UNIQUE,
                senha TEXT NOT NULL,
                
                -- Colunas de Estoque (em ml ou bolsas)
                estoque_a_pos INTEGER NOT NULL DEFAULT 0,
                estoque_a_neg INTEGER NOT NULL DEFAULT 0,
                estoque_b_pos INTEGER NOT NULL DEFAULT 0,
                estoque_b_neg INTEGER NOT NULL DEFAULT 0,
                estoque_ab_pos INTEGER NOT NULL DEFAULT 0,
                estoque_ab_neg INTEGER NOT NULL DEFAULT 0,
                estoque_o_pos INTEGER NOT NULL DEFAULT 0,
                estoque_o_neg INTEGER NOT NULL DEFAULT 0,
                
                -- Metadados
                data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ultima_atualizacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS [update_polo_timestamp]
            AFTER UPDATE ON polos
            BEGIN
                UPDATE polos SET ultima_atualizacao = CURRENT_TIMESTAMP WHERE id = old.id;
            END;
            ''')

            conn.commit()
            print("✅ Estrutura do banco de dados (com endereço estruturado) verificada/criada com sucesso!")
            
        except Error as e:
            print(f"❌ Erro ao inicializar o banco de dados: {e}", file=sys.stderr)
            sys.exit(1)
        finally:
            if conn:
                conn.close()