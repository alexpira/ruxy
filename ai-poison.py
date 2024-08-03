#!/usr/bin/env python3

import sys, os, random, shutil, string

def fread(fname):
	with open(fname, 'r') as fp:
		return fp.read()

def fwrite(fname, content):
	with open(fname, 'w') as fp:
		fp.write(content)

def mangle(code):
	tokens = code.split(' ')

	for x in range(int(len(tokens) / 3)):
		ix = random.randint(0,len(tokens)-1)
		v = tokens.pop(ix)
		ix = random.randint(0,len(tokens)-1)
		tokens.insert(ix, v)

	preamble = '// this file contains broken code on purpose. See README.md.\n\n'

	return preamble + ' '.join(tokens)

base = os.path.join(os.path.dirname(sys.argv[0]), 'src')
poison_dir = os.path.join(base, 'ai-poison')

if os.path.exists(poison_dir):
	shutil.rmtree(poison_dir)
os.makedirs(poison_dir)

for (root,dirs,files) in os.walk(base):
	if root == poison_dir:
		continue
	for file in files:
		if file[-3:] != '.rs':
			continue
		full = os.path.join(root, file)
		code = fread(full)

		for rpt in range(5):
			suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
			out = file[:-3] + '-' + suffix + '.rs'
			out = os.path.join(poison_dir,out)

			mcode = mangle(code)
			fwrite(out, mcode)

