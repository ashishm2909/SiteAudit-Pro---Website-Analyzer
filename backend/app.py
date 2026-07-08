from flask import Flask, render_template, request, jsonify
from analyzer import WebsiteAnalyzer
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, 
    template_folder='../frontend/templates',
    static_folder='../frontend/static'
)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'Please provide a valid URL'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        analyzer = WebsiteAnalyzer(url)
        results = analyzer.analyze()
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5002)
