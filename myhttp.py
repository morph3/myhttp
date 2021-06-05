"""
TODO: implement proxy
TODO: implement sessions
TODO: implement different content types
TODO: implement httpserver
TODO: implement file upload

0x0d -> carriage return, \r
0x0x -> new line, \n

"""
import socket
import ssl
import OpenSSL
from http_parser.http import HttpStream
from http_parser.reader import SocketReader
from urllib.parse import urlparse
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend

class MyHTTPObject:
    def __init__(self, url, port=-1, path='/',method="GET", protocol=1.1 ):
        self.url = url
        self.protocols = ["1.0","0.9","0.8","1.1","2","3"] # , users might wanna change this
        self.methods = ["GET","POST","HEAD","PUT", "OPTIONS", "DELETE", "PATCH", "CONNECT","TRACE"]
        self.hostname = "" # host
        self.host_header = "" # host
        self.path = path
        self.user_agent = "myhttp - github.com/morph3"
        self.method = method
        self.port = 80 # default ? 
        if(port != -1 ): # user supplied a port, lets use it 
            self.port = port
        self.parse_url() # sets self.port, self.is_ssl, self.path 
        self.protocol = protocol
        self.resp = ""
        self.resp_body = ""
        self.place_holder = "" # ? 
        self.resp_headers = ""
        self.additional_headers = []
        self.body_params = ""
        self.request = ""
        pass

    def forge_request(self):
        self.request =  f"{self.method} {self.path} HTTP/{self.protocol}\r\n"
        self.request += f"Host: {self.host_header}\r\n"
        self.request += f"User-Agent: {self.user_agent}\r\n"
        if(len(self.additional_headers) > 0):
            for h in self.additional_headers:
                self.request += f"{h}\r\n"
        #req += f"Accept: */*\r\n
        self.request += "\r\n"
        if(len(self.body_params)> 0):
            self.request += self.body_params
        pass


    def __str__(self):
        return repr(self)

    def parse_url(self):
        parsed_url = urlparse(self.url)
        self.port = parsed_url.port
        #print(f"self.port: {self.port}")
        if parsed_url.scheme == 'http':
            self.is_ssl = False # not needed but w.e
            if self.port == None:
                self.port = 80
        else:
            self.is_ssl = True
            if self.port == None:
                self.port = 443
        if parsed_url.query != '':
            self.path = parsed_url.path+"?"+parsed_url.query
        else:
            self.path = parsed_url.path
        
        if self.path == '':
            self.path = "/"
        self.host_header = parsed_url.hostname
        self.hostname = parsed_url.hostname
        pass
    
    



class MyHTTPClient(MyHTTPObject):
    def __init__(self,host, port=-1, ssl_verify=False, timeout = 3) -> None:
        self.http_object = MyHTTPObject(host,port)
        self.sock = None        
        self.ssl_cert = None
        self.ssl_verify = ssl_verify
        self.timeout = timeout

        pass

    def get(self,path):
        self.http_object.method = "GET"
        self.http_object.path =  path
        self.send()
        return self.http_object

    def post(self,path, data=""):
        # body doesnt have to have a data
        self.http_object.method = "POST"
        self.http_object.path = path
        self.http_object.additional_headers.append("Content-Type: application/x-www-form-urlencoded")
        self.http_object.additional_headers.append(f"Content-Length: {len(data)}") # data can be 0 
        
        self.http_object.body_params = data
        self.send()
        return self.http_object
    
    def send(self):
        # a response object is ready on self.resp after this function gets executed

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.sock.settimeout(self.timeout)
        self.http_object.forge_request()
        if self.http_object.is_ssl == True:
            context = ssl.SSLContext(ssl_version = ssl.PROTOCOL_SSLv23 ) # ssl_version must be None ? 
            if(self.ssl_verify == False):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            self.ssl_sock = context.wrap_socket(self.sock, server_hostname=self.http_object.hostname) # For SNI use server_hostname=self.hostname
            self.ssl_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            self.ssl_sock.connect((self.http_object.hostname, self.http_object.port))
            self.ssl_sock.send(self.http_object.request.encode())
            r = SocketReader(self.ssl_sock)
            self.http_object.resp = HttpStream(r)
            try:
                self.http_object.resp_body = self.http_object.resp.body_file().read().decode('latin1') # ?
                self.http_object.resp_headers = ""
                for key,val in self.resp.headers().items():
                    self.http_object.resp_headers += f"{key}: {val}\n"
            except:
                pass
            #print(dir(self.resp))
            self.ssl_sock.close()
#            self.resp = self.resp.decode()
        else:
            self.sock.connect((self.http_object.hostname, self.http_object.port))
            self.sock.send(self.http_object.request.encode())
            r = SocketReader(self.sock)
            self.http_object.resp = HttpStream(r)
            try:
                self.http_object.resp_body = self.http_object.resp.body_file().read().decode('latin1')
                self.http_object.resp_headers = ""
                for key,val in self.resp.headers().items():
                    self.http_object.resp_headers += f"{key}: {val}\n"
            except:
                pass
            self.sock.close()

    def get_ssl_cert(self):
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.sock.settimeout(self.timeout)
        context = ssl.SSLContext(ssl_version = ssl.PROTOCOL_SSLv23 )
        if(self.ssl_verify == False):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        self.ssl_sock = context.wrap_socket(self.sock, server_hostname=self.http_object.hostname) # For SNI use server_hostname=self.hostname
        self.ssl_sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self.ssl_sock.connect((self.http_object.hostname, self.http_object.port))
        self.ssl_cert = ssl.DER_cert_to_PEM_cert(self.ssl_sock.getpeercert(True))
        self.ssl_sock.close()
        return self.ssl_cert


    def get_prettified_ssl_cert(self):
        if(self.ssl_cert):
            pass
        else:
            self.get_ssl_cert()
        """
        Returns a prettified dict of ssl cert
        """
        ssl_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.ssl_cert)
        subjects = {}
        for subject in ssl_cert.get_subject().get_components():
            subjects[subject[0].decode()] =subject[1].decode() 

        issuers = {}
        for issuer in ssl_cert.get_issuer().get_components():
            issuers[issuer[0].decode()] =issuer[1].decode() 

        prettified_cert = {
            'subject': subjects,
            'issuer': issuers,
            'serialNumber': ssl_cert.get_serial_number(),
            'version': ssl_cert.get_version(),
            'notBefore': datetime.strptime(ssl_cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ'),
            'notAfter': datetime.strptime(ssl_cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ'),
        }

        extensions = (ssl_cert.get_extension(i) for i in range(ssl_cert.get_extension_count()))
        extension_data = {e.get_short_name().decode(): str(e) for e in extensions}
        prettified_cert.update(extension_data)
        #pprint(result)
        return prettified_cert

class MyHTTPSession(MyHTTPClient):
    def __init__(self,host,port=-1) -> None:
        self.http_client = MyHTTPClient(host,port)
        pass

    def get(self):
        self.http_client.get()
        return self.http_client.http_object
    def post(self):
        self.http_client.post()
        return self.http_client.http_object



class MyHTTPServer():
    def __init__(self, host="0.0.0.0", port="8081"):
        pass