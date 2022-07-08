import csv

with open('protocol.csv', newline='') as f:
    reader = csv.reader(f)
    data = list(reader)

for i in range(0,146):
    print(data[i][0])
    print(data[i][1])
