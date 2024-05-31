from json2html import *
import json

input = json.load(open('vt.json', encoding='utf-8'))
h = json2html.convert(json = input)

with open('vt.html', 'w', encoding='utf-8') as f:
    f.write(h)