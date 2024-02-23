import os
import time
from flask import Flask, render_template, send_file, request
import webbrowser
import zipfile
import csv
import plotly.graph_objects as go
import plotly.offline as pyo
from scapy.all import *
from threading import Timer
import glob

app = Flask(__name__)

def openBrowser(port="5000"):
    ip = "http://127.0.0.1:"+str(port)
    webbrowser.open(ip, new=2)

def openDashboard():
    ip = "http://127.0.0.1:5000/dashboard"
    webbrowser.open(ip, new=2)

@app.route('/')
def upload():
    return render_template('upload.html')

@app.route("/download")
def download_file():
    folder_name = "results"
    zip_filename = f"{folder_name}.zip"
    folder_path = os.path.join(os.getcwd(), folder_name)

    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zip:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                zip.write(file_path, os.path.relpath(file_path, folder_path))

    return send_file(zip_filename, as_attachment=True)

@app.route('/network')
def graphtwo():
    return render_template('network.html')

def visualise(csvfile, title):
    labels = []
    values = []

    if os.path.exists(csvfile):

        with open(csvfile, 'r') as csvf:

            lines = csv.reader(csvf, delimiter=',')
            for row in lines:
                if len(row)>1:
                    labels.append(row[0])
                    values.append(int(row[1]))

        fig = go.Figure(
            data=[go.Pie(labels=labels, values=values, pull=[0.1, 0.1, 0.1, 0.1])])
        fig.update_layout(template='seaborn')
        fig.update_layout(title=title)
        h = pyo.plot(fig, include_plotlyjs=False, output_type='div')

        return h

@app.route('/dashboard', methods=['POST', 'GET'])
def worktype():
    
    if request.method == 'POST':
        pcap_files = glob.glob("*.pcap")

        for pcap_file in pcap_files:
            os.remove(pcap_file)
        
        pcap_files = glob.glob("*.pcapng")

        for pcap_file in pcap_files:
            os.remove(pcap_file)
            
        z = request.files['file']
        z.save(z.filename)
                
        os.startfile("backend.exe")
        
        return render_template('upload.html')
    
    if request.method == 'GET':
            
        a = visualise(os.path.join("results","protocol.csv"), "PROTOCOL")
    
        b = visualise(os.path.join("results","vendor.csv"), "VENDOR")

        c = visualise(os.path.join("results","src-ip.csv"), "SOURCE IP")
    
        d = visualise(os.path.join("results","dst-ip.csv"), "DESTINATION IP")
    
        e = visualise(os.path.join("results","src-port.csv"), "SOURCE PORT")
    
        f = visualise(os.path.join("results","dst-port.csv"), "DESTINATION PORT")
    
        g = visualise(os.path.join("results","src-mac.csv"), "SOURCE MAC")
        
        h = visualise(os.path.join("results","dst-mac.csv"), "DESTINATION MAC")
        
        return render_template('work.html', protocol=a, vendor=b, srcip=c, dstip=d, srcport=e, dstport=f, srcmac=g, dstmac=h)
        


if __name__ == "__main__":
    Timer(0.5, openBrowser).start()
    app.run()
