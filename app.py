import multiprocessing
from flask import Flask, render_template
import os 
from flask import request
app = Flask(__name__)
from pcap import pcap
from multiprocessing import Process
import webbrowser

@app.route('/')
def upload():
    return render_template('upload.html')

@app.route('/success', methods = ['POST','GET'])
def success():
    
    return render_template('success.html')

@app.route('/pcap', methods = ['POST','GET'])
def capture():
    if request.method == 'POST':  
        f = request.files['file']
        f.save(f.filename)
        dn = os.path.abspath(f.filename)
        print(dn)
        webbrowser.open_new("http://127.0.0.1:5000/pcap")
        pcap(dn)
        os.remove(f.filename)
    sip = '/static/src-ip.html'
    dip = '/static/dst-ip.html'
    vendor = '/static/vendor.html'
    protocol = '/static/protocol.html'
    sport = '/static/src-port.html'
    dport = '/static/dst-port.html'
    smac = '/static/src-mac.html'
    dmac = '/static/dst-mac.html'
    
    return render_template('home.html',sip=sip, dip=dip,vendor=vendor,protocol=protocol, sport=sport,dport=dport,smac=smac,dmac=dmac)

@app.route('/network-graph')
def graph():
    return render_template('network-graph.html')

if __name__ =='__main__':
    app.run(debug = True)

