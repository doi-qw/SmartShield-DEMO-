from flask import Flask, render_template, request, jsonify
from solidity_scanner import analyze_source
import html

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """
    Ожидает JSON: { "code": "<solidity source text>" }
    Возвращает JSON с результатами анализа (dict от analyze_source)
    """
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({'error': 'No code provided'}), 400
    code = data['code']
    # безопасно: мы не выполняем переданный код, только анализируем текст
    res = analyze_source(code)
    return jsonify(res)

if __name__ == '__main__':
    # debug True для локальной разработки (удалите в продакшн)
    app.run(host='127.0.0.1', port=5000, debug=True)
