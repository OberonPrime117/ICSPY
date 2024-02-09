# ICSPY - A PCAP Parser Configured for ICS/OT environments

### VM SETUP

1. Download Elasticsearch onto EC2 Machine.
   
2. Clone this GitHub repository onto the EC2 Machine.
   
3. Change the configuration in `config/elasticsearch.yml`. Take reference from the repository `setup/elasticsearch.yml`
   
4. Run `elasticsearch` executable inside the `bin` directory.

> NOTE - Upon running the elasticsearch executable, the commandline will print the elasticsearch password. Note this password for future steps.

5. Run the python scripts stored in the `setup` directory from the GitHub repository. These will populate protocols and vendor data for lookup.

### LOCAL MACHINE

1. Download the GitHub repository onto local machine.
   
2. Create a virtual environment `virtualenv` in the root of the project directory.
   
3. Enter the virtual environment.
   
4. Install the necessary python modules via `pip install -r requirements.txt`
   
5. Create `.env` file in the root of the project directory.
   
6. Refer `.env.sample` and fill the elasticsearch password and EC2 instance public DNS.
   
7. Now run the following command in the root of the project directory => `python app.py`

8. Upload the PCAP file into the HTML form.