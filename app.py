
from flask import Flask, render_template, request
from flask_talisman import Talisman
from detector import predict_url, check_malware
import os

app = Flask(__name__)
app.secret_key = 'mysecurekey'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
Talisman(app)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ''
    if request.method == 'POST':
        url = request.form['url']
        file = request.files.get('file')

        result = predict_url(url)
        if file and file.filename:
            path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(path)
            malware = check_malware(path)
            result += f" | Malware: {'Yes' if malware else 'No'}"
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
