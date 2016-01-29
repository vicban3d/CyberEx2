#!/usr/bin/python
'''
cyber assignment 2 question 2 server
'''

from hashlib import sha256
import BaseHTTPServer
import hmac

HOST_NAME = '192.168.1.1'
PORT_NUMBER = 8080

KEY = "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"



class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """
    MyHandler class
    """
    def do_HEAD(self):
        """
        Got HEAD request
        """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
    def do_GET(self):
        """
        Got GET request
        """

        hmac_and_msg = self.rfile.read( \
        	int(self.headers.getheader('content-length')))

        only_hmac = hmac_and_msg[:32]
        only_msg = hmac_and_msg[32:]

        enc_msg = hmac.new(KEY, only_msg, sha256).digest()

        if only_hmac == enc_msg:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("<html><head><title>Ex2 WebServer</title></head>")
            self.wfile.write("<body><p>Welcome to Q2 !!!.</p>")
            self.wfile.write("</body></html>")
            print "Connectd From: " + self.client_address[0]
        else:
            print "Detected Spoofing!"
            self.send_response(401)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("<html><head><title>Ex2 WebServer</title></head>")
            self.wfile.write("<body><p>UNAUTHORIZED ACCESS!!</p>")
            self.wfile.write("</body></html>")



if __name__ == '__main__':
    SERVERCLASS = BaseHTTPServer.HTTPServer
    HTTPD = SERVERCLASS((HOST_NAME, PORT_NUMBER), MyHandler)
    print "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
    try:
        HTTPD.serve_forever()
    except KeyboardInterrupt:
        pass
    HTTPD.server_close()
    print "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)

