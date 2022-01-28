from fileinput import filename
import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt
import missingno as msno

filename = 'summary_mod2.csv'
df = pd.read_csv(filename)
print(df.shape)
# msno.matrix(df).get_figure().savefig('newchart2.png')


