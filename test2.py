from tkinter import *
from tkinterdnd2 import *

def addto_listbox(event):
    lb.insert("end", event.data)

ws = TkinterDnD.Tk()
ws.title('PythonGuides')
ws.geometry('400x300')
ws.config(bg='#fcb103')

frame = Frame(ws)
frame.pack()

lb = Listbox(
    frame, 
    width=50,
    height=15,
    selectmode=SINGLE,
    )
lb.pack(fill=X, side=LEFT)
lb.drop_target_register(DND_FILES)
lb.dnd_bind('<<Drop>>', addto_listbox)

sbv = Scrollbar(
    frame,
    orient=VERTICAL
    )
sbv.pack(side=RIGHT, fill=Y)

lb.configure(yscrollcommand=sbv.set)
sbv.config(command=lb.yview)


ws.mainloop()