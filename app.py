from flask import Flask, render_template, request
from scanner import scan_url, check_sql_injection, check_xss, check_security_headers

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        vulnerabilities = scan_url(url)
        vulnerabilities.extend(check_sql_injection(url))
        vulnerabilities.extend(check_xss(url))
        vulnerabilities.extend(check_security_headers(url))
        return render_template('results.html', url=url, vulnerabilities=vulnerabilities)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
