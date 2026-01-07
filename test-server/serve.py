#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer

V11 = True
CHUNK = True

class WebRequestHandler(BaseHTTPRequestHandler):
	def do_GET(self, method='GET'):
		print(f'{self.request.getpeername()} {method} {self.path}')

		data = None
		for (h,v) in self.headers.items():
			print(f' HDR: {h}: {v}')
			if h.lower() == 'content-length':
				data = self.rfile.read(int(v))

		if (data):
			print(data)

		if V11:
			self.protocol_version = 'HTTP/1.1'
			self.send_response(200, "Yup")
			# Gets closed server side anyway
			self.send_header("Connection", "close")
		else:
			self.send_response(200, "Yup")

		self.send_header("Content-Type", "text/plain")
		self.send_header("X-Sample", "response header")

		if CHUNK:
			payload = "2\r\nHe\r\n3\r\nllo\r\n0\r\n\r\n".encode("utf-8")
			self.send_header("Transfer-encoding", "chunked")
		else:
			payload = "Hello".encode("utf-8")
			self.send_header("Content-Length", len(payload))

		self.end_headers()
		self.wfile.write(payload)

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

