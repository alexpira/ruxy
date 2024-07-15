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

if __name__ == "__main__":
	server = HTTPServer(("0.0.0.0", 8000), WebRequestHandler)
	server.serve_forever()

