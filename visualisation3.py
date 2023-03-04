import plotly.graph_objects as go
import dash
from dash import dcc
from dash import html
import plotly.express as px
import pandas as pd
import csv

app = dash.Dash(__name__)
 
colors = {
    'background': '#F0F8FF',
    'text': '#00008B'
}

#df = pd.read_csv('covid_19_india.csv')

labels = []
values = []
with open('results/protocol.csv', 'r') as csvfile:
    lines = csv.reader(csvfile, delimiter = ',')
    for row in lines:
        labels.append(row[0])
        values.append(int(row[1]))

fig = go.Figure(data=[go.Pie(labels=labels, values=values, pull=[0.1, 0.1, 0.2, 0.1])])
 
app.layout = html.Div(children=[
    html.H1(children='COVID-19 Time Series Dashboard'),
 
    html.Div(children='''
        COVID-19 Dashboard: India.
    '''),
 
    dcc.Graph(
        id='example-graph',
        figure=fig
    )
])


if __name__ == '__main__':
    app.run_server(debug=True)