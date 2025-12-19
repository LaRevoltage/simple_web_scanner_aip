# -*- coding: utf-8 -*-
import requests
from unittest.mock import Mock, patch
from scanner import (
    check_security_headers,
    check_cors,
    check_csp,
    check_insecure_directories,
    crawl_and_scan,
    gather_basic_recon,
    visited_urls
)


class TestGatherBasicRecon:
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_basic_recon_success(self, mock_get, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4",
            "Content-Type": "text/html"
        }
        mock_response.text = '''
            <html>
                <head>
                    <title>Test Site</title>
                    <meta name="generator" content="WordPress 5.8">
                </head>
                <body>
                    <form action="/login"></form>
                    <a href="/page1">Link1</a>
                    <a href="/page2">Link2</a>
                    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
                    <script src="/app.js"></script>
                </body>
            </html>
        '''
        mock_response.cookies = []
        mock_get.return_value = mock_response
        
        result = gather_basic_recon("https://example.com")
        
        assert result["url"] == "https://example.com"
        assert result["status_code"] == 200
        assert result["server"] == "nginx/1.18.0"
        assert result["powered_by"] == "PHP/7.4"
        assert result["title"] == "Test Site"
        assert result["forms_count"] == 1
        assert result["links_count"] == 2
        assert result["scripts_count"] == 2
        assert "WordPress 5.8" in result["technologies"]
        assert "jQuery" in result["technologies"]
        assert result["response_time"] is not None
        mock_print.assert_called_with("[*] Gathering recon for https://example.com")
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_recon_with_cookies(self, mock_get, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html><body></body></html>"
        
        mock_cookie1 = Mock()
        mock_cookie1.name = "session_id"
        mock_cookie1.value = "abc123"
        mock_cookie2 = Mock()
        mock_cookie2.name = "user_token"
        mock_cookie2.value = "xyz789"
        mock_response.cookies = [mock_cookie1, mock_cookie2]
        
        mock_get.return_value = mock_response
        
        result = gather_basic_recon("https://example.com")
        
        assert len(result["cookies"]) == 2
        assert {"name": "session_id", "value": "abc123"} in result["cookies"]
        assert {"name": "user_token", "value": "xyz789"} in result["cookies"]
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_recon_detects_react(self, mock_get, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = '''
            <html>
                <body>
                    <script src="https://unpkg.com/react@17/umd/react.production.min.js"></script>
                </body>
            </html>
        '''
        mock_response.cookies = []
        mock_get.return_value = mock_response
        
        result = gather_basic_recon("https://example.com")
        
        assert "React" in result["technologies"]
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_recon_detects_angular(self, mock_get, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = '''
            <html>
                <body>
                    <script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js"></script>
                </body>
            </html>
        '''
        mock_response.cookies = []
        mock_get.return_value = mock_response
        
        result = gather_basic_recon("https://example.com")
        
        assert "Angular" in result["technologies"]
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_recon_detects_vue(self, mock_get, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = '''
            <html>
                <body>
                    <script src="https://cdn.jsdelivr.net/npm/vue@2.6.14/dist/vue.js"></script>
                </body>
            </html>
        '''
        mock_response.cookies = []
        mock_get.return_value = mock_response
        
        result = gather_basic_recon("https://example.com")
        
        assert "Vue.js" in result["technologies"]
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_recon_non_html_content(self, mock_get, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Server": "Apache/2.4.41",
            "Content-Type": "application/json"
        }
        mock_response.text = '{"status": "ok"}'
        mock_response.cookies = []
        mock_get.return_value = mock_response
        
        result = gather_basic_recon("https://api.example.com")
        
        assert result["status_code"] == 200
        assert result["server"] == "Apache/2.4.41"
        assert result["title"] is None
        assert result["forms_count"] == 0
        assert result["links_count"] == 0
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_recon_no_server_header(self, mock_get, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html><body></body></html>"
        mock_response.cookies = []
        mock_get.return_value = mock_response
        
        result = gather_basic_recon("https://example.com")
        
        assert result["server"] is None
        assert result["powered_by"] is None
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_recon_request_exception(self, mock_get, mock_print):
        mock_get.side_effect = requests.RequestException("Connection error")
        
        result = gather_basic_recon("https://example.com")
        
        assert result["url"] == "https://example.com"
        assert result["status_code"] is None
        assert result["server"] is None
        print_calls = [str(call) for call in mock_print.call_args_list]
        assert any("[Error] Could not gather recon for https://example.com" in str(call) for call in print_calls)
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_recon_no_title(self, mock_get, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html><body><h1>No Title</h1></body></html>"
        mock_response.cookies = []
        mock_get.return_value = mock_response
        
        result = gather_basic_recon("https://example.com")
        
        assert result["title"] is None
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_recon_multiple_technologies(self, mock_get, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = '''
            <html>
                <head>
                    <meta name="generator" content="Drupal 9">
                </head>
                <body>
                    <script src="https://code.jquery.com/jquery.min.js"></script>
                    <script src="https://unpkg.com/react@17/umd/react.min.js"></script>
                </body>
            </html>
        '''
        mock_response.cookies = []
        mock_get.return_value = mock_response
        
        result = gather_basic_recon("https://example.com")
        
        assert len(result["technologies"]) == 3
        assert "Drupal 9" in result["technologies"]
        assert "jQuery" in result["technologies"]
        assert "React" in result["technologies"]
    
    @patch('builtins.print')
    @patch('scanner.requests.get')
    def test_recon_response_time_measured(self, mock_get, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html"}
        mock_response.text = "<html><body></body></html>"
        mock_response.cookies = []
        mock_get.return_value = mock_response
        
        result = gather_basic_recon("https://example.com")
        
        assert result["response_time"] is not None
        assert isinstance(result["response_time"], float)
        assert result["response_time"] >= 0


class TestCheckSecurityHeaders:
    
    @patch('builtins.print')
    def test_all_headers_present(self, mock_print):
        headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": "default-src 'self'"
        }
        issues = check_security_headers("https://example.com", headers)
        assert issues == []
    
    @patch('builtins.print')
    def test_all_headers_missing(self, mock_print):
        headers = {}
        issues = check_security_headers("https://example.com", headers)
        assert len(issues) == 5
        assert "Missing security header: X-Frame-Options" in issues
        assert "Missing security header: X-Content-Type-Options" in issues
        assert "Missing security header: Strict-Transport-Security" in issues
        assert "Missing security header: X-XSS-Protection" in issues
        assert "Missing security header: Content-Security-Policy" in issues
    
    @patch('builtins.print')
    def test_some_headers_missing(self, mock_print):
        headers = {
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'"
        }
        issues = check_security_headers("https://example.com", headers)
        assert len(issues) == 3
        assert "Missing security header: X-Content-Type-Options" in issues
        assert "Missing security header: Strict-Transport-Security" in issues
        assert "Missing security header: X-XSS-Protection" in issues


class TestCheckCors:
    
    @patch('builtins.print')
    def test_cors_wildcard(self, mock_print):
        headers = {"Access-Control-Allow-Origin": "*"}
        issues = check_cors("https://example.com", headers)
        assert len(issues) == 1
        assert "CORS: Access-Control-Allow-Origin is set to '*' (wildcard)" in issues
    
    @patch('builtins.print')
    def test_cors_specific_origin(self, mock_print):
        headers = {"Access-Control-Allow-Origin": "https://trusted.com"}
        issues = check_cors("https://example.com", headers)
        assert issues == []
    
    @patch('builtins.print')
    def test_cors_not_present(self, mock_print):
        headers = {}
        issues = check_cors("https://example.com", headers)
        assert issues == []


class TestCheckCsp:
    
    @patch('builtins.print')
    def test_csp_not_present(self, mock_print):
        headers = {}
        issues = check_csp("https://example.com", headers)
        assert issues == []
    
    @patch('builtins.print')
    def test_csp_unsafe_inline(self, mock_print):
        headers = {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
        issues = check_csp("https://example.com", headers)
        assert len(issues) == 1
        assert "CSP: 'unsafe-inline' detected" in issues
    
    @patch('builtins.print')
    def test_csp_unsafe_eval(self, mock_print):
        headers = {"Content-Security-Policy": "default-src 'self' 'unsafe-eval'"}
        issues = check_csp("https://example.com", headers)
        assert len(issues) == 1
        assert "CSP: 'unsafe-eval' detected" in issues
    
    @patch('builtins.print')
    def test_csp_wildcard_default_src(self, mock_print):
        headers = {"Content-Security-Policy": "default-src *"}
        issues = check_csp("https://example.com", headers)
        assert len(issues) == 1
        assert "CSP: default-src set to wildcard (*)" in issues
    
    @patch('builtins.print')
    def test_csp_multiple_issues(self, mock_print):
        headers = {"Content-Security-Policy": "default-src * 'unsafe-inline' 'unsafe-eval'"}
        issues = check_csp("https://example.com", headers)
        assert len(issues) == 3
        assert "CSP: 'unsafe-inline' detected" in issues
        assert "CSP: 'unsafe-eval' detected" in issues
        assert "CSP: default-src set to wildcard (*)" in issues
    
    @patch('builtins.print')
    def test_csp_secure(self, mock_print):
        headers = {"Content-Security-Policy": "default-src 'self'; script-src 'self'"}
        issues = check_csp("https://example.com", headers)
        assert issues == []


class TestCheckInsecureDirectories:
    
    @patch('builtins.print')
    @patch('scanner.requests.head')
    def test_insecure_directory_found(self, mock_head, mock_print):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_head.return_value = mock_response
        
        issues = check_insecure_directories("https://example.com")
        
        assert len(issues) == 7
        assert "Insecure directory/file found: https://example.com/.git/" in issues
        assert "Insecure directory/file found: https://example.com/.env" in issues
    
    @patch('builtins.print')
    @patch('scanner.requests.head')
    def test_no_insecure_directories(self, mock_head, mock_print):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_head.return_value = mock_response
        
        issues = check_insecure_directories("https://example.com")
        
        assert issues == []
    
    @patch('builtins.print')
    @patch('scanner.requests.head')
    def test_some_directories_found(self, mock_head, mock_print):
        def side_effect(url, timeout):
            mock_response = Mock()
            if '.git/' in url or '.env' in url:
                mock_response.status_code = 200
            else:
                mock_response.status_code = 404
            return mock_response
        
        mock_head.side_effect = side_effect
        
        issues = check_insecure_directories("https://example.com")
        
        assert len(issues) == 2
        assert "Insecure directory/file found: https://example.com/.git/" in issues
        assert "Insecure directory/file found: https://example.com/.env" in issues
    
    @patch('builtins.print')
    @patch('scanner.requests.head')
    def test_request_exception(self, mock_head, mock_print):
        mock_head.side_effect = requests.RequestException("Connection error")
        
        issues = check_insecure_directories("https://example.com")
        
        assert issues == []


class TestCrawlAndScan:
    
    def setup_method(self):
        visited_urls.clear()
    
    @patch('builtins.print')
    @patch('scanner.gather_basic_recon')
    @patch('scanner.requests.get')
    @patch('scanner.check_security_headers')
    @patch('scanner.check_cors')
    @patch('scanner.check_csp')
    @patch('scanner.check_insecure_directories')
    def test_basic_crawl(self, mock_insecure, mock_csp, mock_cors, mock_headers, mock_get, mock_recon, mock_print):
        mock_response = Mock()
        mock_response.headers = {
            "Content-Type": "text/html",
            "X-Frame-Options": "DENY"
        }
        mock_response.text = '<html><body><a href="/page2">Link</a></body></html>'
        mock_get.return_value = mock_response
        
        mock_recon.return_value = {
            "url": "https://example.com",
            "server": None,
            "powered_by": None,
            "technologies": [],
            "status_code": 200,
            "response_time": 0.1,
            "title": None,
            "forms_count": 0,
            "links_count": 0,
            "scripts_count": 0,
            "cookies": []
        }
        
        mock_headers.return_value = []
        mock_cors.return_value = []
        mock_csp.return_value = []
        mock_insecure.return_value = []
        
        crawl_and_scan("https://example.com", max_pages=1)
        
        assert mock_get.called
        assert mock_recon.called
        assert mock_headers.called
        assert mock_cors.called
        assert mock_csp.called
        assert mock_insecure.called
    
    @patch('builtins.print')
    @patch('scanner.gather_basic_recon')
    @patch('scanner.requests.get')
    def test_non_html_content_skipped(self, mock_get, mock_recon, mock_print):
        mock_response = Mock()
        mock_response.headers = {"Content-Type": "application/json"}
        mock_get.return_value = mock_response
        
        mock_recon.return_value = {
            "url": "https://example.com",
            "server": None,
            "powered_by": None,
            "technologies": [],
            "status_code": 200,
            "response_time": 0.1,
            "title": None,
            "forms_count": 0,
            "links_count": 0,
            "scripts_count": 0,
            "cookies": []
        }
        
        crawl_and_scan("https://example.com", max_pages=1)
        
        assert "https://example.com" in visited_urls
    
    @patch('builtins.print')
    @patch('scanner.gather_basic_recon')
    @patch('scanner.requests.get')
    @patch('scanner.check_security_headers')
    @patch('scanner.check_cors')
    @patch('scanner.check_csp')
    @patch('scanner.check_insecure_directories')
    def test_multiple_pages_crawl(self, mock_insecure, mock_csp, mock_cors, mock_headers, mock_get, mock_recon, mock_print):
        def get_side_effect(url, timeout):
            mock_response = Mock()
            mock_response.headers = {"Content-Type": "text/html"}
            if url == "https://example.com":
                mock_response.text = '<html><body><a href="https://example.com/page2">Link</a></body></html>'
            else:
                mock_response.text = '<html><body>Page 2</body></html>'
            return mock_response
        
        mock_get.side_effect = get_side_effect
        mock_recon.return_value = {
            "url": "https://example.com",
            "server": None,
            "powered_by": None,
            "technologies": [],
            "status_code": 200,
            "response_time": 0.1,
            "title": None,
            "forms_count": 0,
            "links_count": 0,
            "scripts_count": 0,
            "cookies": []
        }
        mock_headers.return_value = []
        mock_cors.return_value = []
        mock_csp.return_value = []
        mock_insecure.return_value = []
        
        crawl_and_scan("https://example.com", max_pages=5)
        
        assert len(visited_urls) == 2
    
    @patch('builtins.print')
    @patch('scanner.gather_basic_recon')
    @patch('scanner.requests.get')
    def test_request_exception_handling(self, mock_get, mock_recon, mock_print):
        mock_get.side_effect = requests.RequestException("Connection error")
        mock_recon.return_value = {
            "url": "https://example.com",
            "server": None,
            "powered_by": None,
            "technologies": [],
            "status_code": 200,
            "response_time": 0.1,
            "title": None,
            "forms_count": 0,
            "links_count": 0,
            "scripts_count": 0,
            "cookies": []
        }
        
        crawl_and_scan("https://example.com", max_pages=1)
        
        print_calls = [str(call) for call in mock_print.call_args_list]
        assert any("[Error] Could not fetch https://example.com" in str(call) for call in print_calls)
