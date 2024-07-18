#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer

class WebRequestHandler(BaseHTTPRequestHandler):
	def do_GET(self, method='GET'):
		print(f'{method} {self.path}')

		data = None
		for h in self.headers:
			v = self.headers.get(h)
			print(f' HDR: {h}: {v}')
			if h.lower() == 'content-length':
				data = self.rfile.read(int(v))

		if (data):
			print(data)

		self.send_response(200)
		self.send_header("Content-Type", "text/plain")
		self.end_headers()
		self.wfile.write("Hello".encode("utf-8"))

	def do_POST(self):
		self.do_GET(method='POST')

import ssl, os, sys

if __name__ == "__main__":
	server = HTTPServer(("0.0.0.0", 8000), WebRequestHandler)
	if len(sys.argv) > 1 and sys.argv[1] == 'ssl':
		fold = os.path.dirname(sys.argv[0])
		context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		context.load_cert_chain(os.path.join('cert.pem'), os.path.join(fold, 'key.pem'))
		server.socket = context.wrap_socket(server.socket, server_side=True)
	server.serve_forever()

