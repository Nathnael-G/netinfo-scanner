from flask import Flask, render_template, request, send_file
import socket
import whois
import dns.resolver
from ipwhois import IPWhois
import subprocess
import os
import csv
from datetime import datetime

app = Flask(__name__)
RESULTS_DIR = "results"
os.makedirs(RESULTS_DIR, exist_ok=True)

def run_nmap(ip):
    try:
        result = subprocess.check_output(['nmap', '-F', ip], universal_newlines=True)
        return result
    except Exception as e:
        return f"Error running nmap: {e}"

def get_info(domain):
    info = {"Domain": domain}
    try:
        ip = socket.gethostbyname(domain)
        info["IP"] = ip
    except:
        info["IP"] = "N/A"

    try:
        dns_records = dns.resolver.resolve(domain, 'A')
        info["DNS A"] = [r.to_text() for r in dns_records]
    except:
        info["DNS A"] = "N/A"

    try:
        w = whois.whois(domain)
        info["Registrar"] = w.registrar
        info["Country"] = w.country
    except:
        info["Registrar"] = "N/A"
        info["Country"] = "N/A"

    try:
        obj = IPWhois(info["IP"])
        res = obj.lookup_rdap()
        info["Org"] = res['network']['name']
    except:
        info["Org"] = "N/A"

    try:
        info["Reverse DNS"] = socket.gethostbyaddr(info["IP"])[0]
    except:
        info["Reverse DNS"] = "N/A"

    info["Port Scan"] = run_nmap(info["IP"]) if info["IP"] != "N/A" else "Skipped"
    return info

def save_to_csv(data_list, filename):
    filepath = os.path.join(RESULTS_DIR, filename)
    keys = list(data_list[0].keys())
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data_list)
    return filepath

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    file_path = None
    original_domains = ""
    
    if request.method == 'POST':
        domains_input = request.form.get('domains', '')
        filename_input = request.form.get('filename', '')

        domains = [d.strip() for d in domains_input.split(',') if d.strip()]
        original_domains = domains_input  # Keep for passing back to template

        for domain in domains:
            info = get_info(domain)
            results.append(info)

        if filename_input:
            sanitized_name = "".join(c for c in filename_input if c.isalnum() or c in (' ', '_')).rstrip()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            final_filename = f"{sanitized_name}_{timestamp}.csv"
            file_path = save_to_csv(results, final_filename)
            file_path = os.path.basename(file_path)

    return render_template("index.html", results=results, file_path=file_path, original_domains=original_domains)


@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(RESULTS_DIR, filename), as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
