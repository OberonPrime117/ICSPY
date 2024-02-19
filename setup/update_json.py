import json


def convert_to_dictionary(lst):
    res_dict = {}
    for i in range(0, len(lst), 2):
        mac_prefix = lst[i].replace('-', ':')
        vendor_name = lst[i + 1]
        res_dict["Mac Prefix"] = mac_prefix
        res_dict["Vendor Name"] = vendor_name
    return res_dict


with open('oui.txt', 'r') as file:
    lines = file.readlines()

mac_addresses = []
vendor_details = []

for line in lines:
    eq = line.replace("\t", "").split('\n')
    if "-" in eq[0] and "(hex)" in eq[0]:
        eq2 = eq[0].replace("(hex)", "")
        eq3 = eq2.split("   ")
        if len(eq3) == 3:
            eq3.pop()
        output_dict = convert_to_dictionary(eq3)
        vendor_details.append(output_dict)

with open('vendor.json', 'w') as json_file:
    json.dump(vendor_details, json_file, indent=4)
