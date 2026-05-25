import time
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import ssl
import socket
import dns.resolver

class Scanner:
    def __init__(self, root_domain, cookies=None, cli_mode=False, callback=None, db=None, scan_id=None):
        self.root_domain = root_domain
        self.cli_mode = cli_mode
        self.callback = callback
        self.db = db
        self.scan_id = scan_id
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache'
        })
        if cookies:
            if isinstance(cookies, str):
                for cookie in cookies.split(';'):
                    if '=' in cookie.strip():
                        name, value = cookie.strip().split('=', 1)
                        self.session.cookies.set(name, value)
            elif isinstance(cookies, dict):
                self.session.cookies.update(cookies)

        self.discovered_hosts = set()
        self.endpoints = defaultdict(set)
        self.edges = []
        self.all_requests = []
        self.visited_urls = set()
        self.pending_urls = set()
        self.is_running = True
        self.file_extensions = ['html', 'htm', 'js', 'php', 'py', 'asp', 'aspx', 'jsp', 'do', 'action', 'cgi', 'pl', 'rb', 'go', 'java', 'xml', 'json', 'vue', 'ts', 'tsx', 'jsx']

    def log(self, msg, level='info'):
        if self.cli_mode:
            if level not in ['warning', 'error'] or 'ignoring' not in msg.lower():
                print(f"[{level.upper()}] {msg}")
        else:
            print(f"[*] {msg}")

    def is_allowed_domain(self, host):
        if not host:
            return False
        host = host.lower()
        root = self.root_domain.lower()
        return host == root or host.endswith(f".{root}")

    def extract_subdomains_from_content(self, content, base_url):
        subdomains = set()

        patterns = [
            r'https?://([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.' + re.escape(self.root_domain) + r')',
            r'[\'"]https?://([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.' + re.escape(self.root_domain) + r')[\'"]',
            r'//([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.' + re.escape(self.root_domain) + r')[/\s]',
        ]

        for pattern in patterns:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    subdomains.add(match.lower())
            except:
                pass

        return subdomains

    def get_certificate_domains(self):
        if not self.cli_mode:
            self.log(f"Extracting domains from SSL certificate of {self.root_domain}")
        domains = {self.root_domain}
        try:
            context = ssl.create_default_context()
            test_subdomains = ['www', 'mail', 'api', 'admin', 'app', 'dev', 'test']

            for sub in test_subdomains:
                test_domain = f"{sub}.{self.root_domain}"
                try:
                    with socket.create_connection((test_domain, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=test_domain) as ssock:
                            cert = ssock.getpeercert()
                            san = cert.get('subjectAltName', [])
                            for typ, name in san:
                                if typ == 'DNS' and (name == self.root_domain or name.endswith('.' + self.root_domain)):
                                    domains.add(name)
                            subject = dict(x[0] for x in cert['subject'])
                            if 'commonName' in subject:
                                cn = subject['commonName']
                                if cn == self.root_domain or cn.endswith('.' + self.root_domain):
                                    domains.add(cn)
                except:
                    pass

            with socket.create_connection((self.root_domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.root_domain) as ssock:
                    cert = ssock.getpeercert()
                    san = cert.get('subjectAltName', [])
                    for typ, name in san:
                        if typ == 'DNS' and (name == self.root_domain or name.endswith('.' + self.root_domain)):
                            domains.add(name)
                    subject = dict(x[0] for x in cert['subject'])
                    if 'commonName' in subject:
                        cn = subject['commonName']
                        if cn == self.root_domain or cn.endswith('.' + self.root_domain):
                            domains.add(cn)
        except Exception as e:
            if not self.cli_mode:
                self.log(f"Certificate extraction failed: {e}", 'warning')

        try:
            answers = dns.resolver.resolve(self.root_domain, 'TXT')
            for rdata in answers:
                txt = str(rdata)
                found = re.findall(r'[\w\.-]+\.' + re.escape(self.root_domain), txt)
                for f in found:
                    domains.add(f)
        except:
            pass

        return domains

    def is_alive(self, host):
        for proto in ['https', 'http']:
            url = f"{proto}://{host}"
            try:
                for attempt in range(3):
                    resp = self.session.get(url, timeout=10, allow_redirects=False, stream=False)
                    if resp.status_code in [403, 429]:
                        time.sleep(2 ** attempt)
                        continue
                    if resp.status_code < 500:
                        return proto, url
                    break
            except:
                continue
        return None, None

    def enqueue_url(self, target_url, source_url, method='GET', form_data=None, source_element=''):
        if not self.is_running:
            return
        parsed = urlparse(target_url)
        if not parsed.netloc:
            return
        target_host = parsed.netloc

        if not self.is_allowed_domain(target_host):
            if not self.cli_mode:
                self.log(f"Ignoring external domain: {target_host}", 'warning')
            return

        if target_url in self.visited_urls or target_url in self.pending_urls:
            return

        path = parsed.path or '/'
        if parsed.query:
            full_path = f"{path}?{parsed.query}"
        else:
            full_path = path

        endpoint_key = f"{method} {full_path}"
        is_new_endpoint = endpoint_key not in self.endpoints[target_host]
        self.endpoints[target_host].add(endpoint_key)

        if is_new_endpoint and self.callback:
            self.callback({
                'type': 'new_endpoint',
                'endpoint': {target_host: [endpoint_key]}
            })

        source_host = urlparse(source_url).netloc
        if source_host and target_host and source_host != target_host:
            edge = {
                'source': source_host,
                'target': target_host,
                'method': method,
                'details': full_path,
                'source_element': source_element
            }

            edge_exists = False
            for e in self.edges:
                if e['source'] == source_host and e['target'] == target_host:
                    edge_exists = True
                    break

            if not edge_exists:
                self.edges.append(edge)
                self.discovered_hosts.add(source_host)
                self.discovered_hosts.add(target_host)

                if self.callback:
                    self.callback({
                        'type': 'new_edge',
                        'edge': edge
                    })

                if self.callback:
                    self.callback({
                        'type': 'new_host',
                        'host': target_host
                    })
                    if source_host != self.root_domain:
                        self.callback({
                            'type': 'new_host',
                            'host': source_host
                        })

                if self.db and self.scan_id:
                    self._save_edge_to_db(edge, target_host, endpoint_key)

        if target_host.endswith(self.root_domain) and target_url not in self.visited_urls:
            self.pending_urls.add(target_url)

    def _save_edge_to_db(self, edge, host, endpoint_key):
        if not self.db or not self.scan_id:
            return
        try:
            with self.db.driver.session() as session:
                session.run(
                    "MERGE (h1:Host {id: $src}) SET h1.label = $src_label "
                    "MERGE (h2:Host {id: $dst}) SET h2.label = $dst_label "
                    "MERGE (h1)-[r:COMMUNICATES {method: $method, details: $details}]->(h2)",
                    src=edge['source'], src_label=edge['source'],
                    dst=edge['target'], dst_label=edge['target'],
                    method=edge['method'], details=edge['details']
                )
                session.run(
                    "MATCH (s:Scan {id: $sid}) MATCH (h:Host {id: $hid}) MERGE (s)-[:INCLUDES]->(h)",
                    sid=self.scan_id, hid=edge['source']
                )
                session.run(
                    "MATCH (s:Scan {id: $sid}) MATCH (h:Host {id: $hid}) MERGE (s)-[:INCLUDES]->(h)",
                    sid=self.scan_id, hid=edge['target']
                )
                ep_id = f"{host}|{endpoint_key}"
                session.run(
                    "MERGE (e:Endpoint {id: $eid}) SET e.method_path = $ep, e.host = $host",
                    eid=ep_id, ep=endpoint_key, host=host
                )
                session.run(
                    "MATCH (h:Host {id: $host}) MATCH (e:Endpoint {id: $eid}) MERGE (h)-[:HAS_ENDPOINT]->(e)",
                    host=host, eid=ep_id
                )
        except Exception as e:
            self.log(f"DB save error: {e}", 'error')

    def process_response(self, response, source_url):
        if response.history:
            for r in response.history:
                self.enqueue_url(r.url, source_url, method='REDIRECT', source_element='HTTP redirect')
                self.crawl_url(r.url)
            self.enqueue_url(response.url, source_url, method='REDIRECT', source_element='HTTP redirect')
            self.crawl_url(response.url)
        else:
            self.crawl_url(response.url)

    def crawl_url(self, url):
        if url in self.visited_urls or not self.is_running:
            return

        parsed = urlparse(url)
        if parsed.netloc and not self.is_allowed_domain(parsed.netloc):
            return

        self.visited_urls.add(url)
        if url in self.pending_urls:
            self.pending_urls.discard(url)

        if not self.cli_mode:
            self.log(f"Crawling: {url}")
        try:
            for attempt in range(3):
                resp = self.session.get(url, timeout=15, allow_redirects=True)
                if resp.status_code in [403, 429]:
                    wait = 2 ** attempt
                    if not self.cli_mode:
                        self.log(f"Rate limited, waiting {wait}s", 'warning')
                    time.sleep(wait)
                    continue
                break
            else:
                return

            self.save_request_response(resp.request, resp, url)
            self.process_response(resp, url)

            if resp.text:
                new_subdomains = self.extract_subdomains_from_content(resp.text, url)
                current_host = parsed.netloc or self.root_domain
                for subdomain in new_subdomains:
                    if subdomain not in self.discovered_hosts:
                        self.discovered_hosts.add(subdomain)
                        proto, url_proto = self.is_alive(subdomain)
                        if proto and self.callback:
                            self.callback({
                                'type': 'new_edge',
                                'edge': {
                                    'source': current_host,
                                    'target': subdomain,
                                    'method': 'DISCOVERED',
                                    'details': 'extracted from content'
                                }
                            })

            content_type = resp.headers.get('Content-Type', '').lower()

            if 'text/html' in content_type:
                soup = BeautifulSoup(resp.text, 'lxml')
                for tag in soup.find_all(['a', 'link', 'script', 'img']):
                    attr = 'href' if tag.name in ['a', 'link'] else 'src'
                    if tag.get(attr):
                        target = urljoin(url, tag.get(attr))
                        self.enqueue_url(target, url, method='GET', source_element=f'<{tag.name}>')
                for form in soup.find_all('form'):
                    self.process_form(form, url)
                for script in soup.find_all('script'):
                    if script.string:
                        self.parse_js_code(script.string, url)
                    elif script.get('src'):
                        script_url = urljoin(url, script.get('src'))
                        self.enqueue_url(script_url, url, method='GET', source_element='<script src>')
                        self.crawl_url(script_url)
            elif 'javascript' in content_type or url.endswith('.js'):
                self.parse_js_code(resp.text, url)
            elif any(ext in url for ext in self.file_extensions):
                found = re.findall(r'https?://[^\s\'"<>]+', resp.text)
                for fu in found:
                    self.enqueue_url(fu, url, method='GET', source_element='text content')
        except Exception as e:
            if not self.cli_mode:
                self.log(f"Error crawling {url}: {e}", 'error')

    def process_form(self, form, base_url):
        action = form.get('action', '')
        method = form.get('method', 'get').upper()
        target_url = urljoin(base_url, action)
        target_host = urlparse(target_url).netloc
        if not self.is_allowed_domain(target_host):
            return
        inputs = form.find_all(['input', 'textarea', 'select'])
        form_data = {}
        file_inputs = []
        for inp in inputs:
            name = inp.get('name')
            if not name:
                continue
            inp_type = inp.get('type', 'text').lower()
            if inp_type == 'file':
                file_inputs.append(name)
                form_data[name] = ('test.txt', b'Pentest test content')
            elif inp_type in ['text', 'search', 'email', 'password', 'hidden', 'number']:
                form_data[name] = f"test_{name}_{int(time.time())}"
            elif inp_type == 'checkbox' and inp.get('checked'):
                form_data[name] = 'on'
            elif inp_type == 'radio' and inp.get('checked'):
                form_data[name] = inp.get('value', 'on')
            elif inp_type == 'submit':
                continue
            else:
                form_data[name] = inp.get('value', 'test')
        try:
            if method == 'GET':
                resp = self.session.get(target_url, params=form_data, timeout=10, allow_redirects=True)
            else:
                if file_inputs:
                    files = {name: form_data[name] for name in file_inputs}
                    normal_data = {k: v for k, v in form_data.items() if k not in file_inputs}
                    resp = self.session.post(target_url, data=normal_data, files=files, timeout=10, allow_redirects=True)
                else:
                    resp = self.session.post(target_url, data=form_data, timeout=10, allow_redirects=True)
            self.save_request_response(resp.request, resp, base_url)
            self.process_response(resp, base_url)
            self.enqueue_url(target_url, base_url, method=method, form_data=form_data, source_element='<form>')
        except Exception as e:
            pass

    def parse_js_code(self, js_code, base_url):
        fetch_pattern = r"fetch\s*\(\s*['\"]([^'\"]+)['\"]"
        for url in re.findall(fetch_pattern, js_code):
            full_url = urljoin(base_url, url)
            self.enqueue_url(full_url, base_url, method='FETCH', source_element='JS fetch')
        xhr_pattern = r"\.open\s*\(\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]\s*,\s*['\"]([^'\"]+)['\"]"
        for method, url in re.findall(xhr_pattern, js_code, re.IGNORECASE):
            full_url = urljoin(base_url, url)
            self.enqueue_url(full_url, base_url, method=method.upper(), source_element='JS XHR')
        route_pattern = r"path\s*:\s*['\"](/[^'\"]+)['\"]"
        for route in re.findall(route_pattern, js_code):
            full_url = urljoin(base_url, route)
            self.enqueue_url(full_url, base_url, method='GET', source_element='SPA route')

    def save_request_response(self, req, resp, source_url):
        req_headers = dict(req.headers)
        req_body = req.body if req.body else ''
        if isinstance(req_body, bytes):
            req_body = req_body.decode('utf-8', errors='replace')
        self.all_requests.append({
            'request': {
                'method': req.method,
                'url': req.url,
                'headers': req_headers,
                'body': req_body[:2000],
                'timestamp': time.time()
            },
            'response': {
                'status_code': resp.status_code,
                'headers': dict(resp.headers),
                'body_preview': resp.text[:2000] if resp.text else '',
                'length': len(resp.content)
            },
            'source': source_url
        })

    def scan(self):
        if not self.cli_mode:
            self.log(f"Starting scan for {self.root_domain}")

        domains = self.get_certificate_domains()

        if not self.cli_mode:
            self.log(f"Found {len(domains)} domains from SSL/TXT")

        active_hosts = []
        for domain in domains:
            if not self.is_allowed_domain(domain):
                continue
            proto, url = self.is_alive(domain)
            if proto:
                active_hosts.append((domain, proto))
                self.discovered_hosts.add(domain)
                if not self.cli_mode:
                    self.log(f"Active: {domain}")

        if not active_hosts:
            if not self.cli_mode:
                self.log("No active hosts found!", 'error')
            return self.get_results()

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}

            for host, proto in active_hosts:
                url = f"{proto}://{host}"
                futures[executor.submit(self.crawl_url, url)] = url

            while self.is_running and (futures or self.pending_urls):
                while self.pending_urls and len(futures) < 20:
                    new_url = self.pending_urls.pop()
                    if new_url not in self.visited_urls:
                        futures[executor.submit(self.crawl_url, new_url)] = new_url

                if not futures:
                    break

                done = set()
                for future in as_completed(list(futures.keys())):
                    done.add(future)
                    try:
                        future.result()
                    except Exception as e:
                        pass
                    break

                for future in done:
                    del futures[future]

        return self.get_results()

    def get_results(self):
        unique_edges = []
        seen = set()
        for e in self.edges:
            key = (e['source'], e['target'])
            if key not in seen:
                seen.add(key)
                unique_edges.append(e)

        nodes = [{'id': h, 'label': h} for h in self.discovered_hosts]
        endpoints_serializable = {h: list(paths) for h, paths in self.endpoints.items()}

        return {
            'nodes': nodes,
            'edges': unique_edges,
            'endpoints': endpoints_serializable,
            'requests': self.all_requests,
            'total_requests': len(self.all_requests),
            'total_hosts':
