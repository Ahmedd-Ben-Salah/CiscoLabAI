import os
path = 'C:/Users/GIGABITE/AppData/Local/Programs/Python/Python312/Lib/site-packages/twofish.py'
with open(path, 'r') as f:
    text = f.read()

text = text.replace('import imp\nimport sys', 'import sys\nimport os\nimport glob')
text = text.replace(
    "_twofish = cdll.LoadLibrary(imp.find_module('_twofish')[1])",
    "_dir = os.path.dirname(__file__)\n_pyd = glob.glob(os.path.join(_dir, '_twofish*.pyd'))[0]\n_twofish = cdll.LoadLibrary(_pyd)"
)

with open(path, 'w') as f:
    f.write(text)
