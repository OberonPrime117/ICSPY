g = open("demofile3.txt", "w")
with open("mac-vendors.json", encoding='utf-8-sig') as f:
    read = f.read()
    wr = f.write()
    dicta = json.loads(read)
  for b in dicta:
    if "-" in b["Mac Prefix"]:
        b = b.replace("-",":")
