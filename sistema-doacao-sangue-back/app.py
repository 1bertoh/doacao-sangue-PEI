import sqlite3
from datetime import datetime, timedelta
import functools
import click
from flask_cors import CORS

from flask import Flask, request, jsonify, g
from passlib.hash import sha256_crypt
import jwt

from database import get_db_connection, init_db

app = Flask(__name__)
app.config['SECRET_KEY'] = '3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b'
app.config['JWT_EXPIRATION_DELTA'] = timedelta(hours=24)

origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
CORS(app, resources={r"/api/*": {"origins": origins}})

with app.app_context():
    init_db(app)

# --- Helpers e Decoradores ---

def model_to_dict(model):
    """Converte um objeto sqlite3.Row em um dicionário."""
    if model is None:
        return None
    return dict(model)

def token_required(f):
    """Decorador para proteger rotas com JWT."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'message': 'Formato de token inválido! (Esperado: Bearer <token>)'}), 401

        if not token:
            return jsonify({'message': 'Token está faltando!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            g.current_polo = data
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirou!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token é inválido!'}), 401

        return f(*args, **kwargs)
    return decorated_function

# --- Tratamento de Erros da API ---
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Recurso não encontrado'}), 404

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Requisição inválida', 'message': error.description}), 400

@app.errorhandler(500)
def internal_server_error(error):
    app.logger.error(f"Erro interno do servidor: {error}")
    return jsonify({'error': 'Erro interno do servidor'}), 500

# --- CLI Command para Criar Polo ---
@app.cli.command("create-polo")
@click.option("--nome", required=True, help="Nome do polo de doação.")
@click.option("--email", required=True, help="Email de login do polo.")
@click.option("--senha", required=True, help="Senha de acesso.")
@click.option("--pais", required=True, help="País do polo.")
@click.option("--estado", required=True, help="Estado ou Província (ex: SP).")
@click.option("--cidade", required=True, help="Cidade do polo.")
@click.option("--cep", required=True, help="Código de Endereçamento Postal.")
@click.option("--endereco", required=True, help="Nome da rua/avenida.")
@click.option("--numero", help="Número do endereço.", default="")
@click.option("--complemento", help="Complemento (ex: Apto 101).", default="")
@click.option("--telefone", help="Telefone de contato do polo.", default="")
def create_polo(nome, email, senha, pais, estado, cidade, cep, endereco, numero, complemento, telefone):
    """Cria um novo polo de doação no sistema com endereço completo."""
    try:
        with app.app_context():
            conn = get_db_connection()
            hashed_password = sha256_crypt.hash(senha)
            params = (
                nome, telefone, pais, estado, cidade, cep, endereco, numero, complemento,
                email, hashed_password
            )
            sql = '''INSERT INTO polos (
                         nome_polo, telefone, pais, estado, cidade, cep, endereco, numero, complemento,
                         email, senha
                     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''

            conn.execute(sql, params)
            conn.commit()
            print(f"✅ Polo '{nome}' criado com sucesso!")
    except sqlite3.IntegrityError as e:
        print(f"❌ Erro de integridade: O nome do polo ou o email '{email}' já existe. Detalhe: {e}")
    except Exception as e:
        print(f"❌ Ocorreu um erro inesperado: {e}")
    finally:
        if 'conn' in locals() and conn:
            conn.close()

# ==============================================
# API DE AUTENTICAÇÃO E CADASTRO
# ==============================================

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Autentica um polo e retorna um token JWT."""
    data = request.get_json()
    if not data or not data.get('email') or not data.get('senha'):
        return jsonify({'message': 'Email e senha são obrigatórios'}), 400

    email = data['email']
    senha_candidata = data['senha']

    conn = get_db_connection()
    polo = conn.execute('SELECT * FROM polos WHERE email = ?', (email,)).fetchone()
    conn.close()

    if polo and sha256_crypt.verify(senha_candidata, polo['senha']):
        token_payload = {
            'id': polo['id'],
            'nome_polo': polo['nome_polo'],
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + app.config['JWT_EXPIRATION_DELTA']
        }
        token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token})

    return jsonify({'message': 'Credenciais inválidas!'}), 401

@app.route('/api/polos/register', methods=['POST'])
def register_polo():
    """Permite que um novo polo se cadastre no sistema."""
    data = request.get_json()
    required_fields = ['nome_polo', 'email', 'senha', 'pais', 'estado', 'cidade', 'cep', 'endereco']
    if not data or not all(field in data for field in required_fields):
        return jsonify({'error': 'Campos obrigatórios faltando'}), 400
    
    hashed_password = sha256_crypt.hash(data['senha'])
    
    conn = get_db_connection()
    try:
        params = (
            data['nome_polo'], data.get('telefone', ''), data['pais'], data['estado'], data['cidade'], data['cep'],
            data['endereco'], data.get('numero', ''), data.get('complemento', ''), data['email'], hashed_password
        )
        sql = '''INSERT INTO polos (
                     nome_polo, telefone, pais, estado, cidade, cep, endereco, numero, complemento,
                     email, senha
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''
        
        cursor = conn.cursor()
        cursor.execute(sql, params)
        new_id = cursor.lastrowid
        conn.commit()
        
        new_polo = conn.execute('SELECT * FROM polos WHERE id = ?', (new_id,)).fetchone()
        polo_dict = model_to_dict(new_polo)
        del polo_dict['senha']
        
        return jsonify(polo_dict), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Nome do polo ou email já cadastrado'}), 409
    finally:
        conn.close()

# ==============================================
# API DE GERENCIAMENTO DO POLO (LOGADO)
# ==============================================

@app.route('/api/polos/me', methods=['GET'])
@token_required
def get_me():
    """Retorna os dados do polo atualmente logado."""
    polo_id = g.current_polo['id']
    conn = get_db_connection()
    polo = conn.execute('SELECT * FROM polos WHERE id = ?', (polo_id,)).fetchone()
    conn.close()

    if not polo:
        return jsonify({'error': 'Polo não encontrado'}), 404
        
    polo_dict = model_to_dict(polo)
    del polo_dict['senha']
    return jsonify(polo_dict)

@app.route('/api/polos/me', methods=['PUT'])
@token_required
def update_me():
    """Atualiza os dados cadastrais do polo logado."""
    polo_id = g.current_polo['id']
    data = request.get_json()
    
    updatable_fields = ['nome_polo', 'telefone', 'pais', 'estado', 'cidade', 'cep', 'endereco', 'numero', 'complemento', 'email']
    fields_to_update = {k: v for k, v in data.items() if k in updatable_fields}
    
    if not fields_to_update:
        return jsonify({'error': 'Nenhum campo para atualizar foi fornecido'}), 400
        
    if 'senha' in data:
        fields_to_update['senha'] = sha256_crypt.hash(data['senha'])

    set_clause = ", ".join([f"{key} = ?" for key in fields_to_update.keys()])
    params = list(fields_to_update.values())
    params.append(polo_id)

    sql = f'UPDATE polos SET {set_clause} WHERE id = ?'

    conn = get_db_connection()
    try:
        conn.execute(sql, params)
        conn.commit()
        updated_polo = conn.execute('SELECT * FROM polos WHERE id = ?', (polo_id,)).fetchone()
        polo_dict = model_to_dict(updated_polo)
        del polo_dict['senha']
        return jsonify(polo_dict)
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email ou nome do polo já em uso por outro cadastro'}), 409
    finally:
        conn.close()


@app.route('/api/polos/me/estoque', methods=['PUT'])
@token_required
def update_my_stock():
    """Atualiza o estoque de sangue do polo logado."""
    polo_id = g.current_polo['id']
    data = request.get_json()

    valid_blood_types = [
        'estoque_a_pos', 'estoque_a_neg', 'estoque_b_pos', 'estoque_b_neg',
        'estoque_ab_pos', 'estoque_ab_neg', 'estoque_o_pos', 'estoque_o_neg'
    ]
    
    updates = {key: value for key, value in data.items() if key in valid_blood_types and isinstance(value, int)}

    if not updates:
        return jsonify({'error': 'Nenhum dado de estoque válido fornecido'}), 400

    set_clause = ", ".join([f"{key} = ?" for key in updates.keys()])
    params = list(updates.values())
    params.append(polo_id)
    
    sql = f"UPDATE polos SET {set_clause} WHERE id = ?"
    
    conn = get_db_connection()
    conn.execute(sql, params)
    conn.commit()
    
    stock_data = conn.execute(f"SELECT {', '.join(valid_blood_types)} FROM polos WHERE id = ?", (polo_id,)).fetchone()
    conn.close()
    
    return jsonify(model_to_dict(stock_data))


# ==============================================
# API PÚBLICA DE DADOS
# ==============================================

@app.route('/api/polos/all', methods=['GET'])
def get_all_polos():
    """
    Retorna todos os polos e seus dados de estoque para a página inicial (pública).
    A senha é explicitamente excluída da seleção para segurança.
    """
    conn = get_db_connection()
    fields_to_return = """
        id, nome_polo, telefone, pais, estado, cidade, cep, endereco, numero, 
        complemento, email, estoque_a_pos, estoque_a_neg, estoque_b_pos, 
        estoque_b_neg, estoque_ab_pos, estoque_ab_neg, estoque_o_pos, 
        estoque_o_neg, ultima_atualizacao
    """
    
    polos = conn.execute(f'SELECT {fields_to_return} FROM polos').fetchall()
    conn.close()
    
    return jsonify([model_to_dict(row) for row in polos])


@app.route('/api/polos/busca', methods=['GET'])
def search_blood():
    """
    Busca polos com base no tipo sanguíneo e filtros de localização.
    Exemplo: /api/polos/busca?tipo_sanguineo=a_pos&cidade=São Paulo&estado=SP
    """
    args = request.args
    
    tipo_sanguineo = args.get('tipo_sanguineo')
    if not tipo_sanguineo:
        return jsonify({'error': 'O parâmetro "tipo_sanguineo" é obrigatório.'}), 400
    
    coluna_estoque = f"estoque_{tipo_sanguineo.lower()}"
    
    valid_stock_columns = [
        'estoque_a_pos', 'estoque_a_neg', 'estoque_b_pos', 'estoque_b_neg',
        'estoque_ab_pos', 'estoque_ab_neg', 'estoque_o_pos', 'estoque_o_neg'
    ]
    if coluna_estoque not in valid_stock_columns:
        return jsonify({'error': 'Tipo sanguíneo inválido.'}), 400

    fields_to_return = "id, nome_polo, telefone, pais, estado, cidade, cep, endereco, numero, complemento, email, ultima_atualizacao, " + coluna_estoque

    query = f'SELECT {fields_to_return} FROM polos WHERE {coluna_estoque} > 0'
    params = []
    
    if args.get('cidade'):
        query += ' AND cidade LIKE ?'
        params.append(f"%{args.get('cidade')}%")
    
    if args.get('estado'):
        query += ' AND estado = ?'
        params.append(args.get('estado').upper())
        
    if args.get('nome'):
        query += ' AND nome_polo LIKE ?'
        params.append(f"%{args.get('nome')}%")

    conn = get_db_connection()
    results = conn.execute(query, params).fetchall()
    conn.close()
    
    return jsonify([model_to_dict(row) for row in results])


if __name__ == '__main__':
    app.run(debug=True, port=5001)