from tkinter import *
from tkinterdnd2 import *
import os
import sys

def drop(event):
    global fileloc
    fileloc = str(event.data)
    var.set(event.data)
    

def addto_listbox(event):
    lb.insert("end", event.data)

ws = TkinterDnD.Tk()
ws.title('PythonGuides')
ws.geometry('300x300')
ws.config(bg='#fcba03')


var = StringVar()
Label(ws, text='Path of the Folder', bg='#fcba03').pack(anchor=NW, padx=10)
e_box = Entry(ws, textvar=var, width=80)
e_box.pack(fill=X, padx=10)
e_box.drop_target_register(DND_FILES)
e_box.dnd_bind('<<Drop>>', drop)



lframe = LabelFrame(ws, text='Instructions', bg='#fcba03')
Label(
    lframe, 
    bg='#fcba03',
    text='Drag and drop the folder \nof your choice in the below region.',
    height=5
    ).pack(fill=BOTH)
lframe.pack(fill=BOTH, padx=10, pady=10)
frame = Frame(ws)
frame.pack()
lb = Listbox(
    frame, 
    width=45,
    height=3,
    selectmode=SINGLE,
    )
lb.pack(fill=X, side=LEFT)
lb.drop_target_register(DND_FILES)
lb.dnd_bind('<<Drop>>', drop)

def submitFunction() :
    print('Submit button is clicked.')
    ws.destroy()
    os.system(f'python pcap.py {fileloc}')
 
button_submit = Button(ws, text ="Submit", command=submitFunction)
button_submit.pack(padx=10, pady=10)
button_submit.config(width=20, height=2)
 
button_submit.pack()
ws.mainloop()