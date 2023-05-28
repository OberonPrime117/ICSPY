# pcap-python-parser

Link to mac-vendors file - [here](https://drive.google.com/file/d/1g3bEM2UwhTfZIG3CDh-zTg6mESr2IbgC/view?usp=sharing)

Currently using a raw dump of mac vendors with future plans to use elasticsearch to have quick lookups for mac address lookups

IMP Files - 
1. elasticsearch/elasticworks.py - for pushing mac - vendors data to elasticsearch
2. Edit ELASTIC_PASSWORD with your password for 'elastic' user
3. Comment functions according

Create a virtual environment !! Steps are as follows ->
1. python3 -m venv pcap-python
2. source pcap-python/bin/activate
3. python3 -m pip install -r requirements.txt

And exit virtual env when no longer needed by running "deactivate"

Create results and static folders

Commands To Run ->
1. python pcap.py --pcap pcapfilehere.pcap
2. python app.py

PyInstaller Command ->
$ pyinstaller -D --add-data "templates;templates" --add-data "results;results" --collect-all pyvis --noconfirm app.py

pyinstaller --noconfirm --onedir --windowed --add-data "/home/aditya/Documents/GitHub/python-pcap-parser/virtualpcap:virtualpcap/" --add-data "/home/aditya/Documents/GitHub/python-pcap-parser/templates:templates/" --add-data "/home/aditya/Documents/GitHub/python-pcap-parser/results:results/" --collect-all "pyvis"  "/home/aditya/Documents/GitHub/python-pcap-parser/app.py"