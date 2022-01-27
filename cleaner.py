import os
import subprocess as sp
path = './elfs'
for file in os.listdir(path):
	filepath = path + '/' + file
	
	cmd = "readelf -a " + filepath
	output = sp.getoutput(cmd)
	
	if ("Warning:" in output) or ("Error:" in output):
		print("removing " + file + "...")
		os.remove(filepath)
