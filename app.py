from flask import Flask, render_template
import os 
app = Flask(__name__) #creating the Flask class object
app.jinja_env.auto_reload = True
app.config["TEMPLATES_AUTO_RELOAD"] = True
@app.route('/') #decorator drfines the
def home():
    sip = '/static/src-ip.png'
    dip = '/static/dst-ip.png'
    vendor = '/static/vendor.png'
    protocol = '/static/protocol.png'
    sport = '/static/src-port.png'
    dport = '/static/dst-port.png'
    return render_template('home.html',sip=sip, dip=dip,vendor=vendor,protocol=protocol, sport=sport,dport=dport)
  
if __name__ =='__main__':
    app.run(debug = True)
