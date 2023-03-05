from flask import Flask, render_template
import os 
import webbrowser
app = Flask(__name__) #creating the Flask class object

@app.route('/')
def pcap():
    sip = '/static/src-ip.png'
    dip = '/static/dst-ip.png'
    vendor = '/static/vendor.png'
    protocol = '/static/protocol.png'
    sport = '/static/src-port.png'
    dport = '/static/dst-port.png'
    return render_template('home.html',sip=sip, dip=dip,vendor=vendor,protocol=protocol, sport=sport,dport=dport)
  
if __name__ =='__main__':
    webbrowser.open('http://localhost:5000')
    app.run(debug = True)

