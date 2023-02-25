import json
from mac_vendor_lookup import MacLookup
with open("mac-vendors.json", encoding='utf-8-sig') as f:
	read = f.read()
	dicta = json.loads(read)
i = 0
for b in dicta:
	# DOING MAC LOOKUP 
	#print(b["Mac Prefix"])
	try:
		a = MacLookup().lookup(b["Mac Prefix"])
	except:
		continue
	
	# REPLACE - WITH : FOR MAC ADDRESS UNIFORMITY
	a = a.split(" ")
	a = ' '.join(a)

	g = b["Vendor Name"].split(" ")
	g = ' '.join(g)
	#print(b["Mac Prefix"])
	h = b["Mac Prefix"]
	#h = b["Mac Prefix"].split(" ")
	#h = ''.join(h)
	#h = b["Mac Prefix"].split(":")
	#h = ':'.join(h)
	#print(g)
	#print(f)
	#print(e)
	#print(f)
	if a == g:
		pass
	else:
		#print(str(a)+ " ||||||| "+str(b["Vendor Name"]))
		b["Vendor Name"] = a
#print(str(dicta))
with open("mac-vendors2.json",'w', encoding='utf-8-sig') as f:
	#f.write(str(dicta))
	json.dump(dicta, f, indent = 6)




