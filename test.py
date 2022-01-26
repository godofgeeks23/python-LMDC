dict = {}
dict['name'] = 'Zara'
dict['age'] = 7
dict['class'] = 'First'
for i in range(10):
    dict[f'prop{i}'] = i+100
print(dict)