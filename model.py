from fileinput import filename
from tkinter.tix import Y_REGION
from matplotlib.transforms import Bbox
import pandas as pd
import os
import numpy as np
import matplotlib.pyplot as plt
import missingno as msno
from sklearn.ensemble import ExtraTreesClassifier
from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_fscore_support as score

filename = 'summary_mod2.csv'
df = pd.read_csv(filename)

df = df.drop(['file_name'], axis=1)

features = df.columns.values

csv_features = []
for i in features:
        csv_features.append(i)
print("features: {}".format(csv_features))

data = df[features[:-1]]
target = df[features[-1]]


# height = list(classes)
# bars = ('benign', 'ddos', 'backdoor', 'botnet', 'virus', 'trojan')
# y_pos = np.arange(len(bars))
# plt.bar(y_pos, height, color=['green', 'red', 'blue', 'yellow', 'orange', 'purple'])
# plt.xticks(y_pos, bars)
# plt.xlabel('Classes')
# plt.ylabel('Number of Samples')
# plt.savefig('distribution_count.png')
# plt.show()

X = data
Y = target

model = ExtraTreesClassifier()
model.fit(X, Y)
# print(len(model.feature_importances_))

feature_ranking = {feature_value_pair[0]: feature_value_pair[1] for feature_value_pair in zip(features, model.feature_importances_)}
sorted_feature_ranking = {k:v for k,v in sorted(feature_ranking.items(), key=lambda item: item[1], reverse=True)}
sorted_features = sorted_feature_ranking.keys()
sorted_importance = sorted_feature_ranking.values()

df_features = pd.DataFrame(sorted_feature_ranking.items(), columns=['features', 'importance'])

n_features = X.shape[1]
plt.figure(figsize=(60, 60))
plt.barh(range(n_features), model.feature_importances_, align='edge')
plt.yticks(np.arange(n_features), X.columns.values)
plt.xlabel('Feature Importance')
plt.ylabel('Features')
# plt.savefig('feature_importance.png', bbox_inches='tight')
# plt.show()

classifiers_accuracy = {}
data_train, data_test, target_train, target_test = train_test_split(data, target, test_size=0.3, random_state=42)

rf = RandomForestClassifier()
rf.fit(data_train, target_train)
pred = rf.predict(data_test)

score = accuracy_score(target_test, pred, normalize=True)
print("F1 Score: {}%".format(f1_score(target_test, pred, average='macro')*100))
print("Accuracy: {}%".format(score*100))
# classifiers_accuracy['Random Forest'] = score

