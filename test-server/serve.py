#!/usr/bin/env python

from http.server import BaseHTTPRequestHandler, HTTPServer

class WebRequestHandler(BaseHTTPRequestHandler):
	# ...

	def do_GET(self):
		self.send_response(200)
		self.send_header("Content-Type", "text/plain")
		self.end_headers()
		self.wfile.write("Hello".encode("utf-8"))

	def do_POST(self):
		self.do_GET()

	# ...

if __name__ == "__main__":
	server = HTTPServer(("0.0.0.0", 8000), WebRequestHandler)
	server.serve_forever()

