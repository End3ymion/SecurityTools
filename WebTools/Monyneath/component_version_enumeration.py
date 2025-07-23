import requests, hashlib, re, urllib.parse, collections, json, os
from bs4 import BeautifulSoup
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

def print_ascii_banner():
    ascii_art = r'''
░█████╗░░█████╗░███╗░░░███╗██████╗░░█████╗░███╗░░██╗███████╗███╗░░██╗████████╗
██╔══██╗██╔══██╗████╗░████║██╔══██╗██╔══██╗████╗░██║██╔════╝████╗░██║╚══██╔══╝
██║░░╚═╝██║░░██║██╔████╔██║██████╔╝██║░░██║██╔██╗██║█████╗░░██╔██╗██║░░░██║░░░
██║░░██╗██║░░██║██║╚██╔╝██║██╔═══╝░██║░░██║██║╚████║██╔══╝░░██║╚████║░░░██║░░░
╚█████╔╝╚█████╔╝██║░╚═╝░██║██║░░░░░╚█████╔╝██║░╚███║███████╗██║░╚███║░░░╚═╝░░░
░╚════╝░░╚════╝░╚═╝░░░░░╚═╝╚═╝░░░░░░╚════╝░╚═╝░░╚══╝╚══════╝╚═╝░░╚══╝░░░╚═╝░░░

██╗░░░██╗███████╗██████╗░░██████╗██╗░█████╗░███╗░░██╗
██║░░░██║██╔════╝██╔══██╗██╔════╝██║██╔══██╗████╗░██║
╚██╗░██╔╝█████╗░░██████╔╝╚█████╗░██║██║░░██║██╔██╗██║
░╚████╔╝░██╔══╝░░██╔══██╗░╚═══██╗██║██║░░██║██║╚████║
░░╚██╔╝░░███████╗██║░░██║██████╔╝██║╚█████╔╝██║░╚███║
░░░╚═╝░░░╚══════╝╚═╝░░╚═╝╚═════╝░╚═╝░╚════╝░╚═╝░░╚══╝

███████╗███╗░░██╗██╗░░░██╗███╗░░░███╗███████╗██████╗░░█████╗░████████╗██╗░█████╗░███╗░░██╗
██╔════╝████╗░██║██║░░░██║████╗░████║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║██╔══██╗████╗░██║
█████╗░░██╔██╗██║██║░░░██║██╔████╔██║█████╗░░██████╔╝███████║░░░██║░░░██║██║░░██║██╔██╗██║
██╔══╝░░██║╚████║██║░░░██║██║╚██╔╝██║██╔══╝░░██╔══██╗██╔══██║░░░██║░░░██║██║░░██║██║╚████║
███████╗██║░╚███║╚██████╔╝██║░╚═╝░██║███████╗██║░░██║██║░░██║░░░██║░░░██║╚█████╔╝██║░╚███║
╚══════╝╚╚╝░░╚══╝░╚═════╝░╚═╝░░░░░╚═╝╚══════╝╚═╝░░╚═╝╚═╝░░╚═╝░░░╚═╝░░░╚═╝░╚════╝░╚═╝░░╚══╝
'''
    print(Fore.LIGHTCYAN_EX + ascii_art)

def print_tool_info():
    print(Fore.LIGHTGREEN_EX + "\n📌 Tool: COMPONENT & VERSION ENUMERATOR v5.1")
    print("🔧 Author: Ethical Scanner by 𝑲𝒆𝒐𝒔𝒐𝒗𝒂𝒏𝒏 𝑴𝒐𝒏𝒚𝒏𝒆𝒂𝒕𝒉")
    print("🔎 Purpose: Fingerprint software versions (CMS, plugins, libraries, web servers, OS).")
    print("🌐 Supports scanning external and internal web targets.\n")
    print("💡 Usage: Just enter a full URL when prompted (e.g., http://example.com)\n")

print_ascii_banner()
print_tool_info()

detected_technologies = collections.defaultdict(dict)
scan_output_list = []
current_target_url = ""

def _log(message):
    print(message)
    scan_output_list.append(message)

def _make_request(target_url, method='GET', allow_redirects=True, timeout=10):
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        if method == 'GET': response = requests.get(target_url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        elif method == 'HEAD': response = requests.head(target_url, headers=headers, timeout=timeout, allow_redirects=allow_redirects)
        else: raise ValueError("Unsupported HTTP method")
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException: return None

def _extract_version(text, default_version='Detected'):
    match = re.search(r'(?:v|version|build)?[-_]?(\d+(?:\.\d+){1,3}(?:[-_\.][a-zA-Z0-9]+)*)', text, re.IGNORECASE)
    if match:
        version = match.group(1).strip('.-_ ')
        version = re.sub(r'(\.js|\.css|\.min|\.bundle|\.php)$', '', version, flags=re.IGNORECASE)
        return version
    match = re.search(r'(\d+)', text)
    if match and len(match.group(1)) < 5 and len(match.group(1)) > 0: return match.group(1)
    return default_version

def _add_tech(category, name, version='Detected'):
    current_version_info = detected_technologies[category].get(name)
    if current_version_info is None:
        detected_technologies[category][name] = version
    else:
        if version != 'Detected' and version != 'Unknown':
            if current_version_info == 'Detected' or current_version_info == 'Unknown':
                detected_technologies[category][name] = version
            else:
                current_parts = [int(p) for p in current_version_info.split('.') if p.isdigit()]
                new_parts = [int(p) for p in version.split('.') if p.isdigit()]
                if new_parts > current_parts: detected_technologies[category][name] = version
                elif new_parts == current_parts and len(version) > len(current_version_info): detected_technologies[category][name] = version
        elif version == 'Detected' and current_version_info == 'Unknown':
            detected_technologies[category][name] = version

def detect_from_headers(response):
    if not response: return
    _log(f"\n{Fore.CYAN}--- Analyzing HTTP Headers for Technologies ---{Fore.RESET}")
    headers = response.headers
    if 'Server' in headers:
        server_full_string = headers['Server']
        match = re.search(r'([a-zA-Z0-9\._-]+)(?:/(\d+(?:\.\d+)*))?(?:\s+\(([^)]+)\))?', server_full_string)
        if match:
            server_name, server_version, os_info = match.group(1), match.group(2) or 'Detected', match.group(3)
            _add_tech('Web Server', server_name, server_version)
            if os_info:
                if 'debian' in os_info.lower(): _add_tech('Operating System', 'Debian', 'Detected')
                elif 'ubuntu' in os_info.lower(): _add_tech('Operating System', 'Ubuntu', 'Detected')
                elif 'centos' in os_info.lower(): _add_tech('Operating System', 'CentOS', 'Detected')
                elif 'rhel' in os_info.lower() or 'red hat' in os_info.lower(): _add_tech('Operating System', 'Red Hat', 'Detected')
                elif 'windows' in os_info.lower(): _add_tech('Operating System', 'Windows', 'Detected')
                else: _add_tech('Operating System', os_info, 'Detected')
        else: _add_tech('Web Server', server_full_string, 'Detected')
    if 'X-Powered-By' in headers:
        powered_by = headers['X-Powered-By']
        if 'PHP' in powered_by: _add_tech('Programming Language', 'PHP', _extract_version(powered_by))
        elif 'Express' in powered_by: _add_tech('JS Runtime/Framework', 'Node.js (Express)', _extract_version(powered_by))
        else: _add_tech('Powered By Header', powered_by.split('/')[0].strip(), _extract_version(powered_by))
    if 'CF-Ray' in headers or 'CF-Cache-Status' in headers or headers.get('Server', '').lower() == 'cloudflare': _add_tech('CDN', 'Cloudflare', 'Detected')
    if 'X-Cache' in headers and 'varnish' in headers['X-Cache'].lower(): _add_tech('CDN/Cache', 'Varnish', 'Detected')
    if 'Content-Type' in headers:
        content_type = headers['Content-Type'].lower()
        if 'charset=' in content_type: _add_tech('Encoding', 'Charset', content_type.split('charset=')[-1].strip())
        if 'text/html' in content_type: _add_tech('Content Type', 'HTML Page', 'Detected')
        elif 'application/json' in content_type: _add_tech('Content Type', 'JSON API', 'Detected')
    if 'X-AspNet-Version' in headers: _add_tech('Framework', 'ASP.NET', headers['X-AspNet-Version'])
    if 'X-Drupal-Cache' in headers: _add_tech('CMS', 'Drupal', 'Detected')
    if 'X-Generator' in headers:
        generator_header = headers['X-Generator']
        _add_tech('Meta Tag Generator', generator_header.split(' ')[0].strip(), _extract_version(generator_header))
    if 'Set-Cookie' in headers:
        cookies = headers['Set-Cookie'].lower()
        if re.search(r'wordpress_test_cookie|wp_logged_in_|wordpress_sec_', cookies): _add_tech('CMS', 'WordPress', 'Detected')
        if re.search(r'joomla_remember_me', cookies): _add_tech('CMS', 'Joomla!', 'Detected')
        if re.search(r'laravel_session', cookies): _add_tech('Framework', 'Laravel', 'Detected')
        if re.search(r'ci_session', cookies): _add_tech('Framework', 'CodeIgniter', 'Detected')
        if re.search(r'__next_f|__next_ssr_prefetch', cookies): _add_tech('JS Framework', 'Next.js', 'Detected')
        if re.search(r'phpsessid', cookies): _add_tech('Programming Language', 'PHP', 'Detected (via Session Cookie)')
    if 'Strict-Transport-Security' in headers: _add_tech('Security', 'HSTS', 'Enabled')

def detect_from_html(html_content, base_url):
    _log(f"\n{Fore.CYAN}--- Analyzing HTML Source Code for Technologies ---{Fore.RESET}")
    soup = BeautifulSoup(html_content, 'html.parser')
    generator_meta = soup.find('meta', attrs={'name': 'generator'})
    if generator_meta and 'content' in generator_meta.attrs:
        content = generator_meta['content']
        if 'WordPress' in content: _add_tech('CMS', 'WordPress', _extract_version(content))
        elif 'Joomla!' in content: _add_tech('CMS', 'Joomla!', _extract_version(content))
        elif 'Drupal' in content: _add_tech('CMS', 'Drupal', _extract_version(content))
        elif 'Shopify' in content: _add_tech('E-commerce Platform', 'Shopify', 'Detected')
        elif 'Magento' in content: _add_tech('E-commerce Platform', 'Magento', _extract_version(content))
        elif 'Next.js' in content: _add_tech('JS Framework', 'Next.js', _extract_version(content))
        elif 'React' in content: _add_tech('JS Framework', 'React', _extract_version(content))
        else: _add_tech('Meta Tag Generator', content.split(' ')[0].strip(), _extract_version(content))
    if soup.find('link', attrs={'rel': 'alternate', 'type': 'application/rss+xml'}): _add_tech('Miscellaneous', 'RSS Feed', 'Detected')
    for tag in soup.find_all(['script', 'link']):
        src = tag.get('src') or tag.get('href')
        if src:
            src_lower = src.lower()
            absolute_src = urllib.parse.urljoin(base_url, src)
            if 'cdnjs.cloudflare.com' in src_lower: _add_tech('CDN', 'cdnjs', 'Detected')
            if 'ajax.googleapis.com' in src_lower: _add_tech('CDN', 'Google Hosted Libraries', 'Detected')
            if 'cdn.jsdelivr.net' in src_lower: _add_tech('CDN', 'jsDelivr', 'Detected')
            if 'jquery' in src_lower:
                version = _extract_version(src)
                if version == 'Detected' and absolute_src.endswith('.js'):
                    response = _make_request(absolute_src);
                    if response and response.text:
                        content_version = re.search(r'jQuery JavaScript Library v(\d+\.\d+\.\d+)', response.text) or re.search(r'/*! jQuery v(\d+\.\d+\.\d+)', response.text)
                        if content_version: version = content_version.group(1)
                _add_tech('JS Library', 'jQuery', version)
            if 'jquery-migrate' in src_lower: _add_tech('JS Library', 'jQuery Migrate', _extract_version(src))
            if 'bootstrap' in src_lower:
                version = _extract_version(src)
                if version == 'Detected' and ('.css' in src_lower or '.js' in src_lower):
                    response = _make_request(absolute_src);
                    if response and response.text:
                        css_version = re.search(r'\* Bootstrap v(\d+\.\d+\.\d+)', response.text)
                        if css_version: version = css_version.group(1)
                _add_tech('CSS Framework', 'Bootstrap', version)
            if 'angular.js' in src_lower or 'angular.min.js' in src_lower: _add_tech('JS Framework', 'AngularJS', _extract_version(src))
            if re.search(r'main(\.[\da-f]+)?\.js', src_lower) or re.search(r'polyfills(\.[\da-f]+)?\.js', src_lower) or re.search(r'runtime(\.[\da-f]+)?\.js', src_lower) or re.search(r'chunk-(\w+)\.js', src_lower) or 'zone.js' in src_lower:
                _add_tech('JS Framework', 'Angular', 'Detected'); _add_tech('Programming Language', 'TypeScript', 'Inferred (from Angular/Zone.js)')
            if 'zone.js' in src_lower: _add_tech('JS Library', 'Zone.js', _extract_version(src))
            if re.search(r'react(\.production|\.development)?\.js', src_lower) or 'react-dom' in src_lower: _add_tech('JS Framework', 'React', _extract_version(src))
            if re.search(r'vue(\.min)?\.js', src_lower): _add_tech('JS Framework', 'Vue.js', _extract_version(src))
            if 'splide' in src_lower and ('.js' in src_lower or '.css' in src_lower): _add_tech('JS Library', 'Splide', _extract_version(src))
            if 'font-awesome' in src_lower or 'fontawesome' in src_lower:
                version = _extract_version(src)
                if version == 'Detected' and '.css' in src_lower:
                    response = _make_request(absolute_src);
                    if response and response.text:
                        css_version = re.search(r'Font Awesome (?:Free )?(\d+\.\d+\.\d+)', response.text)
                        if css_version: version = css_version.group(1)
                _add_tech('Icon Library', 'Font Awesome', version)
            if 'twemoji' in src_lower and ('.js' in src_lower): _add_tech('Font scripts', 'Twitter Emoji (Twemoji)', _extract_version(src))
            if 'onsenui' in src_lower: _add_tech('Mobile UI Framework', 'Onsen UI', _extract_version(src))
            if 'wp-block-library' in src_lower or 'wp-includes/js/dist/block-library' in src_lower: _add_tech('WordPress Editor', 'Gutenberg', 'Detected (via core files)')
            elif 'wp-content/plugins/gutenberg' in src_lower: _add_tech('WordPress Plugin', 'Gutenberg', _extract_version(src))
    body_tag = soup.find('body')
    if body_tag and 'class' in body_tag.attrs:
        body_classes = ' '.join(body_tag['class'])
        if re.search(r'wordpress|wp-admin-bar|wp-custom-css', body_classes, re.IGNORECASE): _add_tech('CMS', 'WordPress', 'Detected (via body classes)')
        if re.search(r'admin-bar', body_classes, re.IGNORECASE) and not 'WordPress' in detected_technologies['CMS']: _add_tech('CMS', 'WordPress', 'Detected (via admin bar class)')
        if re.search(r'joomla', body_classes, re.IGNORECASE): _add_tech('CMS', 'Joomla!', 'Detected (via body classes)')
        if re.search(r'drupal', body_classes, re.IGNORECASE): _add_tech('CMS', 'Drupal', 'Detected (via body classes)')
        if re.search(r'kadence', body_classes, re.IGNORECASE): _add_tech('WordPress Theme', 'Kadence WP', 'Detected (via body class)')
    if soup.find(id=re.compile(r'wp-custom-css|wp-toolbar', re.IGNORECASE)) or soup.find(class_=re.compile(r'wp-admin-bar', re.IGNORECASE)): _add_tech('CMS', 'WordPress', 'Detected (via ID/Class)')
    if soup.find(class_=re.compile(r'joomla|com_content', re.IGNORECASE)): _add_tech('CMS', 'Joomla!', 'Detected (via Class)')
    if soup.find(id='block-drupal-content') or soup.find(id=re.compile(r'drupal-\d+', re.IGNORECASE)): _add_tech('CMS', 'Drupal', 'Detected (via ID)')
    if soup.find(attrs={'ng-app': True}) or soup.find(attrs={'ng-version': True}):
        ng_version_tag = soup.find(attrs={'ng-version': True})
        if ng_version_tag and 'ng-version' in ng_version_tag.attrs: _add_tech('JS Framework', 'Angular', ng_version_tag['ng-version'])
        else: _add_tech('JS Framework', 'Angular', 'Detected')
        _add_tech('Programming Language', 'TypeScript', 'Inferred (from Angular)')
    for script in soup.find_all('script'):
        script_text = script.string
        if script_text:
            if 'window.ng' in script_text or 'ng.probe' in script_text: _add_tech('JS Framework', 'Angular', 'Detected (via JS variable)'); _add_tech('Programming Language', 'TypeScript', 'Inferred (from Angular)')
            if 'window.Zone' in script_text and 'zone.js' in script_text: _add_tech('JS Library', 'Zone.js', 'Detected (via JS variable)'); _add_tech('Programming Language', 'TypeScript', 'Inferred (from Zone.js)')
            if 'Express' in script_text or 'res.render' in script_text or 'app.use' in script_text: _add_tech('JS Runtime/Framework', 'Node.js (Express)', 'Detected (via inline JS)')
            if re.search(r'__REACT_DEVTOOLS_GLOBAL_HOOK__', script_text): _add_tech('JS Framework', 'React', 'Detected (via DevTools Hook)')
            if 'umami.js' in script_text or 'data-website-id' in script_text: _add_tech('Analytics', 'Umami', 'Detected')
    for comment in soup.find_all(string=lambda text: isinstance(text, type(soup.comment))):
        comment_lower = comment.lower()
        if 'wordpress' in comment_lower: _add_tech('CMS', 'WordPress', _extract_version(comment_lower))
        elif 'joomla!' in comment_lower: _add_tech('CMS', 'Joomla!', _extract_version(comment_lower))
        elif 'drupal' in comment_lower: _add_tech('CMS', 'Drupal', _extract_version(comment_lower))
        elif 'generator: grav' in comment_lower: _add_tech('CMS', 'Grav', _extract_version(comment_lower))
        elif 'angular' in comment_lower and 'cli' in comment_lower: _add_tech('JS Framework', 'Angular (CLI)', _extract_version(comment_lower)); _add_tech('Programming Language', 'TypeScript', 'Inferred (from Angular CLI)')
        elif 'php' in comment_lower: _add_tech('Programming Language', 'PHP', _extract_version(comment_lower))

def check_common_paths(base_url):
    _log(f"\n{Fore.CYAN}--- Checking Common Paths for Technologies ---{Fore.RESET}")
    common_paths = {
        'WordPress': ['wp-login.php', 'wp-admin/', 'wp-content/'], 'Joomla!': ['administrator/', 'media/jui/'],
        'Drupal': ['core/misc/', 'sites/all/'], 'Magento': ['js/mage/', 'skin/frontend/'],
        'Laravel': ['vendor/composer/installed.json', 'storage/', '.env'], 'Vue.js': ['/js/app.js', '/mix-manifest.json'],
        'React': ['/static/js/main.', '/index.html'], 'Shopify': ['/cart', '/products'],
        'PrestaShop': ['/themes/', '/admin/'], 'OpenCart': ['/catalog/view/'],
        'Ghost': ['/ghost/'], 'Typo3': ['/typo3/', 'typo3/sysext/'],
        'ASP.NET': ['/web.config', '/bin/'], 'PHPMyAdmin': ['/phpmyadmin/'],
        'Jenkins': ['/jenkins/'], 'nginx': ['/nginx_status'], 'Apache': ['/server-status'],
        'Node.js': ['/package.json', '/server.js', '/dist/main.js'],
        'Angular': ['/main.js', '/polyfills.js', '/runtime.js', '/vendor.js'],
        'Onsen UI': ['/onsenui.min.css', '/onsenui.min.js'],
        'Font Awesome': ['/fontawesome.min.css', '/font-awesome.min.css'], 'PHP': ['/phpinfo.php', '/info.php'],
        'MySQL': ['/phpmyadmin/', '/admin/mysql'], 'Twemoji': ['/twemoji.min.js'],
        'Splide': ['/splide.min.js', '/splide.min.css'], 'Kadence WP Blocks': ['/wp-content/plugins/kadence-blocks/'],
        'Kadence WP': ['/wp-content/themes/kadence/style.css']
    }
    for tech_name, paths in common_paths.items():
        already_detected_strongly = False
        for category_key in detected_technologies:
            if tech_name in detected_technologies[category_key] and detected_technologies[category_key][tech_name] not in ['Detected', 'Unknown']:
                already_detected_strongly = True; break
        if already_detected_strongly: continue
        for path in paths:
            full_url = urllib.parse.urljoin(base_url, path)
            response = _make_request(full_url, method='HEAD')
            if response and (response.status_code == 200 or (response.status_code in [301, 302] and (('login' in response.headers.get('Location', '').lower()) or ('admin' in response.headers.get('Location', '').lower()) or (tech_name.split(' ')[0].lower() in response.headers.get('Location', '').lower())))):
                _add_tech('Possible (Path-Based)', tech_name, 'Detected')
                if path == '/package.json':
                    pkg_response = _make_request(urllib.parse.urljoin(base_url, '/package.json'), method='GET')
                    if pkg_response and pkg_response.status_code == 200:
                        try:
                            pkg_data = json.loads(pkg_response.text)
                            if 'name' in pkg_data and 'version' in pkg_data: _add_tech('Node.js Project', pkg_data['name'], pkg_data['version'])
                            if 'dependencies' in pkg_data:
                                for dep, ver in pkg_data['dependencies'].items():
                                    if 'angular' in dep.lower(): _add_tech('JS Framework', 'Angular', _extract_version(ver))
                                    elif 'react' in dep.lower(): _add_tech('JS Framework', 'React', _extract_version(ver))
                                    elif 'vue' in dep.lower(): _add_tech('JS Framework', 'Vue.js', _extract_version(ver))
                                    elif 'express' in dep.lower(): _add_tech('JS Runtime/Framework', 'Node.js (Express)', _extract_version(ver))
                        except json.JSONDecodeError: _log(f"{Fore.YELLOW}Could not parse package.json at {full_url} (JSON decode error){Fore.RESET}")
                elif path in ['/phpinfo.php', '/info.php']:
                    phpinfo_response = _make_request(full_url, method='GET')
                    if phpinfo_response and phpinfo_response.status_code == 200:
                        php_version_match = re.search(r'<h1 class="p">PHP Version ([\d\.]+)</h1>', phpinfo_response.text) or re.search(r'PHP Version ([\d\.]+)', phpinfo_response.text)
                        if php_version_match: _add_tech('Programming Language', 'PHP', php_version_match.group(1))
                elif path == '/wp-content/themes/kadence/style.css':
                    kadence_theme_response = _make_request(full_url, method='GET')
                    if kadence_theme_response and kadence_theme_response.status_code == 200:
                        version_match = re.search(r'Version:\s*([\d\.]+)', kadence_theme_response.text)
                        _add_tech('WordPress Theme', 'Kadence WP', version_match.group(1) if version_match else 'Detected')
                elif path == '/wp-content/plugins/kadence-blocks/':
                    readme_url = urllib.parse.urljoin(full_url, 'readme.txt')
                    readme_response = _make_request(readme_url, method='GET')
                    if readme_response and readme_response.status_code == 200:
                        version_match = re.search(r'Stable tag:\s*([\d\.]+)', readme_response.text)
                        _add_tech('WordPress Plugin', 'Kadence WP Blocks', version_match.group(1) if version_match else 'Detected')
                    else: _add_tech('WordPress Plugin', 'Kadence WP Blocks', 'Detected')
                break

def display_tech_results(url):
    results_header = f"\n{Fore.GREEN}========================================{Fore.RESET}\n"
    results_header += f"{Fore.GREEN}      DETECTED TECHNOLOGIES{Fore.RESET}\n"
    results_header += f"{Fore.GREEN}        URL: {url}{Fore.RESET}\n"
    results_header += f"{Fore.GREEN}========================================{Fore.RESET}\n"
    _log(results_header)
    if not detected_technologies: _log(f"{Fore.YELLOW}No significant technologies detected.{Fore.RESET}")
    else:
        category_order = ['Web Server', 'Operating System', 'Programming Language', 'Databases', 'CMS', 'WordPress Theme', 'WordPress Plugin', 'WordPress Editor', 'JS Framework', 'JS Library', 'CSS Framework', 'Mobile UI Framework', 'Analytics', 'CDN', 'Security', 'Icon Library', 'Font scripts', 'Powered By Header', 'Meta Tag Generator', 'Content Type', 'Node.js Project', 'Framework', 'Miscellaneous', 'Encoding', 'Possible (Path-Based)']
        for category in category_order:
            if category in detected_technologies and detected_technologies[category]:
                _log(f"\n{Fore.BLUE}[{category}]{Fore.RESET}:")
                for tech_name, version in sorted(detected_technologies[category].items()): _log(f"  - {tech_name}: {version}")
    _log(f"{Fore.GREEN}========================================{Fore.RESET}")

def try_https_then_http(target_input):
    for scheme in ["https://", "http://"]:
        url = scheme + target_input
        try:
            r = _make_request(url, method='HEAD', timeout=5, allow_redirects=True)
            if r and r.status_code:
                _log(f"{Fore.GREEN}[+] Using {scheme.upper().rstrip('://')} for scan.{Fore.RESET}")
                return url
        except requests.RequestException: continue
    _log(f"{Fore.RED}[!] Could not connect with HTTPS or HTTP.{Fore.RESET}"); return None

def main_enumerator_scan():
    global detected_technologies, scan_output_list, current_target_url
    try:
        raw_input = input("Enter target URL or IP: ").strip()
        if not raw_input: _log(f"{Fore.RED}No URL entered. Exiting.{Fore.RESET}"); return
        target_url = raw_input if raw_input.startswith(("http://", "https://")) else try_https_then_http(raw_input)
        if not target_url: _log(f"{Fore.RED}[x] Scan failed due to connection issues.{Fore.RESET}"); return
        current_target_url = target_url
        scan_start_time = datetime.now()
        _log(f"\n{Fore.LIGHTCYAN_EX}--- Starting Component & Version Enumeration for: {target_url} (Local Time: {scan_start_time.strftime('%Y-%m-%d %H:%M:%S')})---{Fore.RESET}")
        initial_response = _make_request(target_url, method='GET')
        if not initial_response: _log(f"{Fore.RED}Could not retrieve initial page content for technology detection. Aborting detailed scan.{Fore.RESET}")
        else:
            detect_from_headers(initial_response)
            detect_from_html(initial_response.text, target_url)
            check_common_paths(target_url)
        display_tech_results(target_url)
        _log(f"\n{Fore.GREEN}[✓] Component & Version Enumeration completed.{Fore.RESET}")
    except KeyboardInterrupt: _log(f"\n{Fore.YELLOW}[!] Scan aborted by user.{Fore.RESET}")
    except Exception as e: _log(f"{Fore.RED}[x] An unexpected error occurred: {e}{Fore.RESET}")
    finally:
        default_filename_base = re.sub(r'[^a-zA-Z0-9.\-_]', '_', current_target_url).strip('_')
        if not default_filename_base: default_filename_base = "scan_results"
        suggested_filename = f"{default_filename_base}_{scan_start_time.strftime('%Y%m%d_%H%M%S')}.txt"
        user_filename = input(f"Enter filename to save results (test.txt): ").strip()
        filename_to_save = user_filename if user_filename else suggested_filename
        try:
            with open(filename_to_save, 'w', encoding='utf-8') as f:
                f.write(f"Component and Version Enumeration Results for: {current_target_url}\n")
                f.write(f"Scan Time (Local): {scan_start_time.strftime('%Y-%m-%d %H:%M:%S %Z')}\n\n")
                for line in scan_output_list: f.write(re.sub(r'\x1b\[[0-9;]*m', '', line) + '\n')
            _log(f"\n{Fore.GREEN}Scan results saved to: {filename_to_save}{Fore.RESET}")
        except IOError as e: _log(f"{Fore.RED}Error saving results to file: {e}{Fore.RESET}")

if __name__ == "__main__":
    main_enumerator_scan()