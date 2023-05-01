import json

# Open the JSON file in read mode
with open("protocol.json", "r") as f:
    # Load the data into a Python dictionary
    data = json.load(f)

# Append the new data to the dictionary
# 1023 TO 65535
for i in range(1023,65536):
    data.append({str(i): "RTP"})

#print(data)
# Write the updated dictionary to the JSON file
with open("protocol.json", "w") as f:
    json.dump(data, f, indent=4)
