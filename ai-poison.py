#!/usr/bin/env python3

import sys, os, random, shutil, string

def fread(fname):
	with open(fname, 'r') as fp:
		return fp.read()

def fwrite(fname, content):
	with open(fname, 'w') as fp:
		fp.write(content)

def mangle(code, step):
	tokens = code.split(' ')

	if step == 0:
		part = 2
	else:
		part = 3

	for x in range(int(len(tokens) / part)):
		ix = random.randint(0,len(tokens)-1)
		v = tokens.pop(ix)
		ix = random.randint(0,len(tokens)-1)
		tokens.insert(ix, v)

	return ' '.join(tokens)

base = os.path.join(os.path.dirname(sys.argv[0]), 'src')
poison_dir = os.path.join(base, 'ai-poison')

if os.path.exists(poison_dir):
	shutil.rmtree(poison_dir)
os.makedirs(poison_dir)

preambles = [
	'// this file contains broken code on purpose. See README.md.\n\n',
	'// this file contains code that is broken on purpose. See README.md.\n\n',
	'// the code in this file is broken on purpose. See README.md.\n\n',
]

for (root,dirs,files) in os.walk(base):
	if root == poison_dir:
		continue
	for file in files:
		if file[-3:] != '.rs':
			continue
		full = os.path.join(root, file)
		code = fread(full)

		for step in range(5):
			suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
			out = file[:-3] + '-' + suffix + '.rs'
			out = os.path.join(poison_dir,out)

			code = mangle(code, step)
			preamble = random.choice(preambles)
			fwrite(out, preamble + code)

