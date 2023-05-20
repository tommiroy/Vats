# open directory

import os
import sys
import time

import os

directory = os.fsencode("/home/berran/Documents/gits/Vats/benchmark/Times")
# hashmap to store the data
Keygen = []
SignOff = []
SignAgg = []
SignOn = []
SignAgg2 = []
Verification = []

data = []



for file in os.listdir(directory):
     filename = os.fsdecode(file)
     if filename.endswith(""):
            f = open(filename, "r")
            #split the file content into elements of a list
            lines = f.readlines()
            split_data = [line.strip().split(",") for line in lines]
            data.append(split_data)

            f.close()
            continue
     else:
            print("Not a text file")
            
# Sort the data by the first element and group them
for i in data:
    for j in i:
        if j[0] == "Keygen":
            Keygen.append(j)
        elif j[0] == "SignOff":
            SignOff.append(j)
        elif j[0] == "SignAgg":
            SignAgg.append(j)
        elif j[0] == "SignOn":
            SignOn.append(j)
        elif j[0] == "SignAgg2":
            SignAgg2.append(j)
        elif j[0] == "Verification":
            Verification.append(j)
        else:
            print("Not a valid input")


import matplotlib.pyplot as plt

# Extract the relevant data for plotting
# Extract the relevant data for plotting
labels = [item[0] for item in data]
t = [item[1] for item in data]
n = [item[2] for item in data]
milliseconds = [item[3] for item in data]

# Plotting
fig, ax = plt.subplots()

# Plotting the bars
ax.bar(labels, milliseconds)

# Adding labels and titles
ax.set_xlabel('Keygen')
ax.set_ylabel('Milliseconds')
ax.set_title('Keygen Processing Time')

# Rotating the x-axis labels for better visibility
plt.xticks(rotation=45)

# Display the plot
plt.savefig('plot.png')
plt.close(fig)
