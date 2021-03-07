import csv
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from scipy.interpolate import interp1d
import datetime as dt
from typing import List
import argparse

#---------------------------------Functions-----------------------------------#

def toCurrents(charges: List):
    for i in range(len(charges)-1):
        charges[i]['value'] = (charges[i]['value'] - charges[i+1]['value'])/(charges[i]['end']-charges[i]['start'])*3600
    return charges[:-1]

def saturate(liste: List, threshold: int):
    for element in liste:
        if (abs(element['value']) > threshold):
            element['value'] = np.sign(element['value'])*threshold

def print_graphs(x: np.array, y1: List, y2: List):
    fig, axs = plt.subplots(2)
    axs[0].plot(x, y1)
    axs[1].plot(x, y2)
    plt.show()

def first_nan(x: np.array):
    bools = np.isnan(x)
    for i in range(len(bools)):
        if not bools[i]:
            return i
    raise

def last_nan(x: np.array, start: int):
    bools = np.isnan(x)
    for i in range(start, len(bools)):
        if bools[i]:
            return i
    raise

def build_list(start: int, end: int, liste: List)->tuple:
    x = []
    y = []
    for i in liste:
        if 0 < i['start'] - start < end:
            x.append(i['start']-start)
            y.append(i['value'])
    return x,y

def power_calculator(charges: List, voltages: List):
    currents = toCurrents(charges)
    voltages.pop()
    saturate(currents, 1)
    saturate(voltages, 7000)

    # Calculate start and end time
    start = max(voltages[0]['start'], currents[0]['start'])
    time_currents = currents[-1]['end']
    time_voltages = voltages[-1]['end']
    end = min(time_currents, time_voltages) - start

    x_currents, y_currents = build_list(start,end, currents)
    x_voltages, y_voltages = build_list(start,end, voltages)
   
    # Build piecewise function from lists
    times = np.arange(0, end, 1000)
    f_voltages = interp1d(x_voltages, y_voltages,assume_sorted=True,bounds_error=False)
    interpolated_voltages = f_voltages(times)
    start_voltages = first_nan(interpolated_voltages)
    end_voltages = last_nan(interpolated_voltages, start_voltages)

    f_currents = interp1d(x_currents, y_currents,assume_sorted=True,bounds_error=False)
    interpolated_currents = f_currents(times)
    start_currents = first_nan(interpolated_currents)
    end_currents = last_nan(interpolated_currents, start_currents)

    # Calculates new starting and ending times
    new_start = max(start_currents, start_voltages)
    new_end = min(end_currents, end_voltages)

    temp_end = 0
    temp_start = 0
    new_times = times[new_start:new_end]/1000
    new_currents = interpolated_currents[new_start:new_end]
    new_voltages = interpolated_voltages[new_start:new_end]
    if(args['graphs']):
        print_graphs(new_times, new_currents, new_voltages)
    if(args['end'] is not None):
        temp_end = dt.datetime.strptime(args['end'],'%d/%m/%Y %H:%M:%S')
        temp_end = ((temp_end - epoch).total_seconds() - 3600) * 1000.0
        if(not start<=temp_end<=end+start):
            print("Wrong end value")
            exit()
        else:
            temp_end = temp_end - start
    if(args['start'] is not None):
        temp_start = dt.datetime.strptime(args['start'],'%d/%m/%Y %H:%M:%S')
        temp_start = ((temp_start - epoch).total_seconds() - 3600) * 1000.0
        if(not start<=temp_start<=end+start):
            print("Wrong start value")
            exit()
        else:
            temp_start = temp_start - start
    try:
        start = next(x[0] for x in enumerate(new_times) if x[1] > temp_start/1000)
    except:
        start = 0
    try:
        end = next(x[0] for x in enumerate(new_times) if x[1] > temp_end/1000)
    except:
        end = len(new_times)-1

    #Calculate mean
    sum = 0
    for i in range(start, end):
        sum += new_currents[i]*new_voltages[i] + new_currents[i+1]*new_voltages[i+1]
    sum += new_currents[-1]*new_voltages[-1]
    return sum*CONVERT/(new_times[end]-new_times[start])

#-----------------------------------Main-------------------------------------#
epoch = dt.datetime.utcfromtimestamp(0)
COULOMB = "Coulomb charge"
VOLTAGE = "Voltage"
CONVERT = 0.001
STEP = 1

parser = argparse.ArgumentParser(description='Calculate average power consumption based on output from battery-historian.')
parser.add_argument('-f','--file', help='input file', type=str, required=True)
parser.add_argument('-s','--start', help='start time (dd/MM/yyyy hh:mm:ss)', type=str, required=False)
parser.add_argument('-e','--end', help='end time (dd/MM/yyyy hh:mm:ss)', type=str, required=False)
parser.add_argument('-g','--graphs', help='print graphs', dest='graphs', action='store_true', required=False)
parser.set_defaults(graphs=False)

args = vars(parser.parse_args())
charges = []
voltages = []
with open(args['file'], newline='') as csvfile:
    reader = csv.reader(csvfile)
    for row in reader:
        if (row[0] == COULOMB):
            charges.append({'start': int(row[2]), 'end': int(row[3]), 'value': float(row[4])})
        elif (row[0] == VOLTAGE):
            voltages.append({'start': int(row[2]), 'end': int(row[3]), 'value': float(row[4])})
print(f"{round(power_calculator(charges, voltages),3)}")
