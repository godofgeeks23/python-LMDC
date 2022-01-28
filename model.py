from fileinput import filename
from tkinter.tix import Y_REGION
import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt
import missingno as msno
from sklearn.ensemble import ExtraTreesClassifier

filename = 'summary_mod2.csv'
df = pd.read_csv(filename)
print(df.shape)
# msno.matrix(df).get_figure().savefig('newchart2.png')

# print(df.head)
df = df.drop(['file_name'], axis=1)

features = df.columns.values
data = df[features[:-1]]
target = df[features[-1]]

classes = target.value_counts()
print(classes)

height = list(classes)
bars = ('benign', 'ddos', 'backdoor', 'botnet', 'virus', 'trojan')
y_pos = np.arange(len(bars))
plt.bar(y_pos, height, color=['green', 'red', 'blue', 'yellow', 'orange', 'purple'])
plt.xticks(y_pos, bars)
plt.xlabel('Classes')
plt.ylabel('Number of Samples')
# plt.savefig('distribution_count.png')
# plt.show()

X = data
Y = target

model = ExtraTreesClassifier(n_estimators=100)
model.fit(X, Y)
print(len(model.feature_importances_))

feature_ranking = {feature_value_pair[0]: feature_value_pair[1] for feature_value_pair in zip(features, model.feature_importances_)}

sorted_feature_ranking = {k:v for k,v in sorted(feature_ranking.items(), key=lambda item: item[1], reverse=True)}

sorted_features = sorted_feature_ranking.keys()
sorted_importance = sorted_feature_ranking.values()

df_features = pd.DataFrame(sorted_feature_ranking.items(), columns=['features', 'importance'])

n_features = X.shape[1]
plt.figure(figsize=(18, 18))
plt.barh(range(n_features), model.feature_importances_, align='edge')
plt.yticks(np.arange(n_features), X.columns.values)
plt.xlabel('Feature Importance')
plt.ylabel('Features')
plt.show()


