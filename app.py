from flask import Flask, render_template, request, jsonify
import html
import subprocess
import json
import tempfile
import os

app = Flask(__name__, static_folder='static', template_folder='templates')

def analyze_with_ast_scanner(code):
    """
    Вызывает Node.js сканер через subprocess
    """
    try:
        # Создаем временный файл с кодом Solidity
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        try:
            # Вызываем Node.js сканер
            result = subprocess.run(
                ['node', 'solidity_scanner_ast.js', temp_file],
                capture_output=True,
                text=True,
                timeout=30  # 30 секунд таймаут
            )
            
            if result.returncode == 0:
                # Парсим JSON вывод
                return json.loads(result.stdout)
            else:
                return {
                    'error': f'Scanner error: {result.stderr}',
                    'functions': [],
                    'global_msgs': []
                }
                
        finally:
            # Удаляем временный файл
            os.unlink(temp_file)
            
    except subprocess.TimeoutExpired:
        return {
            'error': 'Scan timeout (30 seconds)',
            'functions': [],
            'global_msgs': []
        }
    except Exception as e:
        return {
            'error': f'Internal error: {str(e)}',
            'functions': [],
            'global_msgs': []
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """
    Ожидает JSON: { "code": "<solidity source text>" }
    Возвращает JSON с результатами анализа
    """
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({'error': 'No code provided'}), 400
    
    code = data['code']
    
    # Проверяем минимальную длину
    if len(code.strip()) < 10:
        return jsonify({'error': 'Code too short'}), 400
    
    # Вызываем новый AST сканер
    res = analyze_with_ast_scanner(code)
    return jsonify(res)

if __name__ == '__main__':
    # debug True для локальной разработки
    app.run(host='127.0.0.1', port=5000, debug=True)
