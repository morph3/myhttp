import myhttp
import unittest


class TestSum(unittest.TestCase):

    def test_get_request(self):
        cli = myhttp.MyHTTPClient("http://m3.wtf")
        r = cli.get("/test.txt")
        self.assertEqual(r.resp_body, "morph3\n", "Testing for GET request failed")

    def test_post_request(self):
        data = "foo=12&bar=19&test=xxx"
        cli = myhttp.MyHTTPClient("http://m3.wtf:8081")
        r = cli.post("/test.php",data)
        self.assertEqual(r.resp_body, "31xxx", "Testing for POST request failed")

    def test_ssl_get_request(self):
        cli = myhttp.MyHTTPClient("https://morph3sec.com")
        r = cli.get("/test.txt")
        self.assertEqual(r.resp_body, "morph3\n", "Testing for SSL GET request failed")

    def test_ssl_post_request(self):
        cli = myhttp.MyHTTPClient("https://morph3sec.com")
        r = cli.post("/test.txt")
        self.assertEqual(r.resp_body, "morph3\n", "Testing for SSL POST request failed")


    def test_ssl_certificate(self):

        cli = myhttp.MyHTTPClient("https://morph3sec.com")
        r = cli.get("/")
        ssl_cert = cli.get_pretified_ssl_cert() # some form of request must be done before it
        self.assertEqual(ssl_cert["serialNumber"], 310900643139603994721994072218679395285278, "Testing for SSL certificate failed")


if __name__ == "__main__":
    unittest.main()
