# -*- coding: utf-8 -*-
"""Простой сканер веб-уязвимостей.

Этот модуль предоставляет инструменты для сканирования веб-приложений
на наличие простых неправильных конфигураций безопасности.
"""

import argparse
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

visited_urls = set()


def check_security_headers(url, headers):
    """Проверяет наличие важных заголовков безопасности HTTP.

    Args:
        url (str): URL для проверки.
        headers (dict): Словарь HTTP заголовков ответа.

    Returns:
        list: Список строк с описанием отсутствующих заголовков безопасности.
            Пустой список, если все заголовки присутствуют.

    Example:
        >>> headers = {"X-Frame-Options": "DENY"}
        >>> issues = check_security_headers("https://example.com", headers)
        >>> print(issues)
        ['Missing security header: X-Content-Type-Options', ...]
    """
    issues = []
    security_headers = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "X-XSS-Protection",
        "Content-Security-Policy"
    ]
    print(f"[*] Checking headers for {url}")
    for header in security_headers:
        if header not in headers:
            issues.append(f"Missing security header: {header}")
    return issues


def check_cors(url, headers):
    """Проверяет конфигурацию CORS на наличие небезопасных настроек.

    Args:
        url (str): URL для проверки.
        headers (dict): Словарь HTTP заголовков ответа.

    Returns:
        list: Список строк с описанием проблем CORS.
            Пустой список, если проблем не обнаружено.

    Example:
        >>> headers = {"Access-Control-Allow-Origin": "*"}
        >>> issues = check_cors("https://example.com", headers)
        >>> print(issues)
        ["CORS: Access-Control-Allow-Origin is set to '*' (wildcard)"]
    """
    print(f"[*] Checking CORS for {url}")
    issues = []
    if "Access-Control-Allow-Origin" in headers:
        acao = headers["Access-Control-Allow-Origin"]
        if acao == "*":
            issues.append("CORS: Access-Control-Allow-Origin is set to '*' (wildcard)")
    return issues


def check_csp(url, headers):
    """Проверяет Content Security Policy на наличие небезопасных директив.

    Args:
        url (str): URL для проверки.
        headers (dict): Словарь HTTP заголовков ответа.

    Returns:
        list: Список строк с описанием проблем CSP.
            Пустой список, если CSP отсутствует или настроен безопасно.

    Example:
        >>> headers = {"Content-Security-Policy": "default-src 'unsafe-inline'"}
        >>> issues = check_csp("https://example.com", headers)
        >>> print(issues)
        ["CSP: 'unsafe-inline' detected"]
    """
    print(f"[*] Checking CSP for {url}")
    issues = []
    if "Content-Security-Policy" not in headers:
        return issues
    csp = headers["Content-Security-Policy"]
    if "'unsafe-inline'" in csp:
        issues.append("CSP: 'unsafe-inline' detected")
    if "'unsafe-eval'" in csp:
        issues.append("CSP: 'unsafe-eval' detected")
    if "default-src *" in csp:
        issues.append("CSP: default-src set to wildcard (*)")
    return issues


def gather_basic_recon(url):
    """Собирает базовую информацию о веб-приложении.

    Выполняет HTTP запрос и извлекает метаданные о веб-приложении,
    включая информацию о сервере, используемых технологиях, структуре страницы.

    Args:
        url (str): URL для анализа.

    Returns:
        dict: Словарь с информацией о веб-приложении, содержащий:
            - url (str): Целевой URL.
            - server (str or None): Информация о сервере из заголовка Server.
            - powered_by (str or None): Технология из заголовка X-Powered-By.
            - technologies (list): Список обнаруженных технологий.
            - status_code (int or None): HTTP статус код ответа.
            - response_time (float or None): Время ответа в секундах.
            - title (str or None): Заголовок страницы.
            - forms_count (int): Количество форм на странице.
            - links_count (int): Количество ссылок на странице.
            - scripts_count (int): Количество скриптов на странице.
            - cookies (list): Список словарей с информацией о cookies.

    Example:
        >>> info = gather_basic_recon("https://example.com")
        >>> print(info["server"])
        'nginx/1.18.0'
        >>> print(info["technologies"])
        ['WordPress 5.8', 'jQuery']
    """
    recon_info = {
        "url": url,
        "server": None,
        "powered_by": None,
        "technologies": [],
        "status_code": None,
        "response_time": None,
        "title": None,
        "forms_count": 0,
        "links_count": 0,
        "scripts_count": 0,
        "cookies": []
    }
    
    print(f"[*] Gathering recon for {url}")
    
    try:
        import time
        start_time = time.time()
        response = requests.get(url, timeout=5)
        response_time = time.time() - start_time
        
        recon_info["status_code"] = response.status_code
        recon_info["response_time"] = round(response_time, 3)
        
        if "Server" in response.headers:
            recon_info["server"] = response.headers["Server"]
        
        if "X-Powered-By" in response.headers:
            recon_info["powered_by"] = response.headers["X-Powered-By"]
        
        if response.cookies:
            recon_info["cookies"] = [{"name": cookie.name, "value": cookie.value} for cookie in response.cookies]
        
        if "text/html" in response.headers.get("Content-Type", ""):
            soup = BeautifulSoup(response.text, "html.parser")
            
            title_tag = soup.find("title")
            if title_tag:
                recon_info["title"] = title_tag.get_text().strip()
            
            recon_info["forms_count"] = len(soup.find_all("form"))
            recon_info["links_count"] = len(soup.find_all("a"))
            recon_info["scripts_count"] = len(soup.find_all("script"))
            
            meta_generator = soup.find("meta", attrs={"name": "generator"})
            if meta_generator and meta_generator.get("content"):
                recon_info["technologies"].append(meta_generator.get("content"))
            
            for script in soup.find_all("script", src=True):
                src = script.get("src", "")
                if "jquery" in src.lower():
                    recon_info["technologies"].append("jQuery")
                elif "react" in src.lower():
                    recon_info["technologies"].append("React")
                elif "angular" in src.lower():
                    recon_info["technologies"].append("Angular")
                elif "vue" in src.lower():
                    recon_info["technologies"].append("Vue.js")
            
            recon_info["technologies"] = list(set(recon_info["technologies"]))
        
        return recon_info
        
    except requests.RequestException as e:
        print(f"[Error] Could not gather recon for {url}: {e}")
        return recon_info


def check_insecure_directories(url):
    """Проверяет наличие чувствительных директорий и файлов.

    Выполняет HEAD запросы к списку потенциально чувствительных путей
    для обнаружения случайно доступных файлов и директорий.

    Args:
        url (str): Базовый URL для проверки.

    Returns:
        list: Список строк с описанием найденных чувствительных директорий/файлов.
            Пустой список, если ничего не найдено.

    Example:
        >>> issues = check_insecure_directories("https://example.com")
        >>> print(issues)
        ['Insecure directory/file found: https://example.com/.git/']
    """
    issues = []
    insecure_dirs = [".git/", ".svn/", ".env", "backup/", "admin/", "config/", "logs/"]
    print(f"[*] Checking for insecure directories on {url}...")
    for dir_path in insecure_dirs:
        target_url = urljoin(url, dir_path)
        try:
            response = requests.head(target_url, timeout=3)
            if response.status_code == 200:
                issues.append(f"Insecure directory/file found: {target_url}")
        except requests.RequestException:
            pass
    return issues


def crawl_and_scan(start_url, max_pages=10):
    """Выполняет краулинг и сканирование веб-сайта на уязвимости.

    Обходит страницы сайта, начиная с start_url, и проверяет каждую страницу
    на наличие проблем безопасности. Ограничивается одним доменом и максимальным
    количеством страниц.

    Args:
        start_url (str): Начальный URL для сканирования.
        max_pages (int, optional): Максимальное количество страниц для обхода.
            По умолчанию 10.

    Returns:
        None: Функция выводит результаты в консоль.

    Example:
        >>> crawl_and_scan("https://example.com", max_pages=5)
        Starting scan on https://example.com
        Target domain: example.com
        --------------------------------------------------
        [*] Gathering recon for https://example.com
        [+] Server: nginx/1.18.0
        [+] Technologies: WordPress 5.8, jQuery
        [*] Checking headers for https://example.com
        [!] Missing security header: X-Frame-Options
        ...
        --------------------------------------------------
        Scan complete. Visited 5 pages.
    """
    parsed_uri = urlparse(start_url)
    domain = parsed_uri.netloc
    queue = [start_url]
    pages_visited = 0
    print(f"Starting scan on {start_url}")
    print(f"Target domain: {domain}")
    print("-" * 50)
    
    recon_info = gather_basic_recon(start_url)
    if recon_info["server"]:
        print(f"[+] Server: {recon_info['server']}")
    if recon_info["powered_by"]:
        print(f"[+] Powered by: {recon_info['powered_by']}")
    if recon_info["title"]:
        print(f"[+] Title: {recon_info['title']}")
    if recon_info["technologies"]:
        print(f"[+] Technologies: {', '.join(recon_info['technologies'])}")
    if recon_info["response_time"]:
        print(f"[+] Response time: {recon_info['response_time']}s")
    print(f"[+] Forms: {recon_info['forms_count']}, Links: {recon_info['links_count']}, Scripts: {recon_info['scripts_count']}")
    if recon_info["cookies"]:
        print(f"[+] Cookies found: {len(recon_info['cookies'])}")
    print("-" * 50)
    while queue and pages_visited < max_pages:
        url = queue.pop(0)
        if url in visited_urls:
            continue
        visited_urls.add(url)
        pages_visited += 1
        try:
            response = requests.get(url, timeout=5)
            if "text/html" not in response.headers.get("Content-Type", ""):
                continue
            header_issues = check_security_headers(url, response.headers)
            for issue in header_issues:
                print(f"[!] {issue}")
            soup = BeautifulSoup(response.text, "html.parser")
            cors_issues = check_cors(url, response.headers)
            for issue in cors_issues:
                print(f"[!] {issue}")
            csp_issues = check_csp(url, response.headers)
            for issue in csp_issues:
                print(f"[!] {issue}")
            if pages_visited == 1:
                dir_issues = check_insecure_directories(url)
                for issue in dir_issues:
                    print(f"[!] {issue}")
            for link in soup.find_all("a"):
                href = link.get("href")
                if not href:
                    continue
                full_url = urljoin(url, href)
                parsed_href = urlparse(full_url)
                if parsed_href.netloc == domain and parsed_href.scheme in [
                    "http",
                    "https",
                ]:
                    if full_url not in visited_urls and full_url not in queue:
                        queue.append(full_url)
        except requests.RequestException as e:
            print(f"[Error] Could not fetch {url}: {e}")
    print("-" * 50)
    print(f"Scan complete. Visited {pages_visited} pages.")


def main():
    """Точка входа для запуска сканера из командной строки.

    Парсит аргументы командной строки и запускает сканирование.

    Example:
        $ python scanner.py https://example.com --max-pages 20
    """
    parser = argparse.ArgumentParser(description="Simple Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--max-pages", type=int, default=10, help="Maximum pages to crawl"
    )
    args = parser.parse_args()
    target_url = args.url
    if not target_url.startswith("http"):
        target_url = "http://" + target_url
    crawl_and_scan(target_url, args.max_pages)


if __name__ == "__main__":
    main()
