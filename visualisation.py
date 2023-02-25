import random
from matplotlib import pyplot as plt 
import numpy as np 
from matplotlib.animation import FuncAnimation 
fig,ax = plt.subplots()

labels = ['Frogs', 'Hogs', 'Dogs', 'Logs']
sizes = [15, 30, 45, 10]

def animate(i):
    new_sizes = []
    new_sizes = random.sample(sizes, len(sizes))
    print(new_sizes)
    ax.clear()
    ax.axis('equal')
    ax.pie(new_sizes, labels=labels, autopct='%1.1f%%', shadow=True, startangle=140) 

#hello = 
anim = FuncAnimation(fig, animate , frames=100, repeat=False) 

plt.show()