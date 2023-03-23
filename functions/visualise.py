import os
import plotly.graph_objects as go
import csv

def visualise(img_static, csvfile):
    labels = []
    values = []

    if os.path.isfile(csvfile):

        with open(csvfile, 'r') as csvf:

            lines = csv.reader(csvf, delimiter = ',')
            for row in lines:
                labels.append(row[0])
                values.append(int(row[1]))

        fig = go.Figure(data=[go.Pie(labels=labels, values=values, pull=[0.1, 0.1, 0.2, 0.1])])
        fig.write_image(img_static)
        a = img_static.split(".")
        fig.write_html(a[0]+".html")