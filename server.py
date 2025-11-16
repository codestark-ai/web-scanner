# ==============================================
# server.py — Advanced Security Header Evaluator
# ==============================================
from flask import Flask, request, jsonify, send_from_directory
from server import app 
from flask_cors import CORS
import requests
import os
import re
import json
import socket
from urllib.parse import urlparse, urljoin
import base64

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

# ---------- Serve Frontend ----------
@app.route("/")
def serve_frontend():
    return send_from_directory("static", "index.html")

# ---------- Security Header Evaluator ----------
@app.route("/api/headers")
def get_headers():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "Missing URL"}), 400

    try:
        response = requests.get(url, timeout=8)
        headers = {k.lower(): v for k, v in response.headers.items()}
        status = response.status_code
        content = response.text

        # --- Check HTTP methods (OPTIONS, TRACE) ---
        methods_enabled = {}
        for method in ["OPTIONS", "TRACE"]:
            try:
                m_res = requests.request(method, url, timeout=6)
                methods_enabled[method] = (m_res.status_code < 400)
            except Exception:
                methods_enabled[method] = False

        # --- Evaluate CSP strength ---
        csp_header = headers.get("content-security-policy", "")
        csp_warnings = []
        if not csp_header:
            csp_warnings.append("❌ No Content-Security-Policy header found.")
        else:
            if "*" in csp_header:
                csp_warnings.append("⚠️ Wildcard (*) found in CSP — unsafe source allowed.")
            if "unsafe-inline" in csp_header or "unsafe-eval" in csp_header:
                csp_warnings.append("⚠️ CSP allows unsafe-inline or unsafe-eval scripts.")
            if len(csp_header) < 40:
                csp_warnings.append("⚠️ CSP too short — may not provide full protection.")
            if not csp_warnings:
                csp_warnings.append("✅ CSP appears reasonably strong.")

        # --- Detect Server Version Exposure ---
        server_exposure = []
        server_header = headers.get("server")
        x_powered_by = headers.get("x-powered-by")

        if server_header:
            if any(ch.isdigit() for ch in server_header):
                server_exposure.append(f"❌ Server version exposed: {server_header}")
            else:
                server_exposure.append(f"⚠️ Server header present: {server_header}")

        if x_powered_by:
            if any(ch.isdigit() for ch in x_powered_by):
                server_exposure.append(f"❌ X-Powered-By exposes version: {x_powered_by}")
            else:
                server_exposure.append(f"⚠️ X-Powered-By present: {x_powered_by}")

        if not server_exposure:
            server_exposure.append("✅ No server or framework version information exposed.")

        # --- New Vulnerability Checks ---
        vulnerability_findings = perform_vulnerability_checks(url, content, headers)

        return jsonify({
            "status": status,
            "headers": headers,
            "methods_enabled": methods_enabled,
            "csp_warnings": csp_warnings,
            "server_exposure": server_exposure,
            "vulnerability_findings": vulnerability_findings,
            "scanned_url": url
        })

    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

def perform_vulnerability_checks(url, content, headers):
    findings = []
    parsed_url = urlparse(url)
    base_domain = parsed_url.netloc
    
    # 1. CAPTCHA Implementation Check
    captcha_findings = check_captcha_implementation(content, base_domain)
    findings.extend(captcha_findings)

    # 2. Direct IP Access Check
    ip_access = check_ip_access(url)
    if ip_access["accessible"]:
        findings.append({
            "type": "ip_access",
            "area": "Server Configuration",
            "severity": "low",
            "message": "⚠️ Direct IP access is enabled",
            "description": f"Site accessible via IP: {ip_access['ip']}",
            "recommendation": "Configure virtual hosts to reject IP-based access",
            "affected_host": ip_access['ip'],
            "vulnerable_component": "Web Server Configuration",
            "evidence": f"Successfully accessed {ip_access['ip']} directly"
        })

    # 3. Source Code Analysis for Secrets
    secrets_found = analyze_source_code(content, url, base_domain)
    if secrets_found:
        findings.extend(secrets_found)

    # 4. JWT Token Analysis (if found in cookies)
    jwt_analysis = analyze_jwt_tokens(headers, base_domain)
    if jwt_analysis:
        findings.extend(jwt_analysis)

    # 5. Private IP Disclosure
    private_ips = find_private_ips(content)
    if private_ips:
        findings.append({
            "type": "private_ip",
            "area": "Information Disclosure",
            "severity": "high",
            "message": f"❌ Private IP addresses disclosed",
            "description": f"Found {len(private_ips)} internal network IPs exposed in source code",
            "recommendation": "Remove internal IP addresses from client-side code",
            "affected_host": base_domain,
            "vulnerable_component": "Application Source Code",
            "evidence": f"Private IPs found: {', '.join(private_ips[:3])}"
        })

    # 6. Directory Listing Check
    dir_listing_findings = check_directory_listing(url, base_domain)
    if dir_listing_findings:
        findings.extend(dir_listing_findings)

    # 7. Backup Files Check
    backup_files_findings = check_backup_files(url, base_domain)
    if backup_files_findings:
        findings.extend(backup_files_findings)

    # 8. SQL Error Detection
    sql_errors = detect_sql_errors(content)
    if sql_errors:
        findings.append({
            "type": "sql_error",
            "area": "Application Security",
            "severity": "high",
            "message": "❌ SQL error messages detected",
            "description": "Database error messages exposed to users",
            "recommendation": "Implement proper error handling and custom error pages",
            "affected_host": base_domain,
            "vulnerable_component": "Error Handling Module",
            "evidence": "SQL error patterns found in response content"
        })

    # 9. Clickjacking Protection
    clickjacking = check_clickjacking(headers)
    if not clickjacking:
        findings.append({
            "type": "clickjacking",
            "area": "Client Security",
            "severity": "medium",
            "message": "❌ Clickjacking protection missing",
            "description": "X-Frame-Options or Content-Security-Policy frame-ancestors not properly configured",
            "recommendation": "Implement X-Frame-Options: DENY or CSP frame-ancestors directive",
            "affected_host": base_domain,
            "vulnerable_component": "Security Headers Configuration",
            "evidence": "Missing X-Frame-Options and frame-ancestors in CSP"
        })

    # 10. SSL/TLS Check (basic)
    ssl_issues = check_ssl_issues(url)
    if ssl_issues:
        findings.append({
            "type": "ssl_issues",
            "area": "Transport Security",
            "severity": "high",
            "message": "❌ SSL/TLS security issues detected",
            "description": ssl_issues,
            "recommendation": "Update SSL/TLS configuration and use strong ciphers",
            "affected_host": base_domain,
            "vulnerable_component": "SSL/TLS Configuration",
            "evidence": ssl_issues
        })

    # 11. Security Headers Check
    security_headers_findings = check_security_headers(headers, base_domain)
    findings.extend(security_headers_findings)

    # 12. Subdomain Discovery
    subdomain_findings = check_common_subdomains(base_domain)
    if subdomain_findings:
        findings.extend(subdomain_findings)

    # 13. Server Version Disclosure
    version_findings = check_server_version_disclosure(headers, base_domain)
    findings.extend(version_findings)

    # 14. Framework Detection
    framework_findings = detect_frameworks(content, headers, base_domain)
    findings.extend(framework_findings)

    return findings

def check_captcha_implementation(content, base_domain):
    """Check for CAPTCHA implementations and identify vulnerable components"""
    findings = []
    
    # Check for CAPTCHA in forms
    forms_without_captcha = []
    captcha_indicators = ['recaptcha', 'g-recaptcha', 'hcaptcha', 'captcha', 'data-sitekey']
    
    # Look for login forms without CAPTCHA
    login_form_indicators = ['login', 'signin', 'password', 'username']
    form_pattern = r'<form[^>]*>.*?</form>'
    forms = re.findall(form_pattern, content, re.IGNORECASE | re.DOTALL)
    
    for form in forms:
        form_lower = form.lower()
        is_login_form = any(indicator in form_lower for indicator in login_form_indicators)
        has_captcha = any(indicator in form_lower for indicator in captcha_indicators)
        
        if is_login_form and not has_captcha:
            forms_without_captcha.append("Login Form")
    
    # Check contact forms
    contact_indicators = ['contact', 'message', 'enquiry', 'feedback']
    for form in forms:
        form_lower = form.lower()
        is_contact_form = any(indicator in form_lower for indicator in contact_indicators)
        has_captcha = any(indicator in form_lower for indicator in captcha_indicators)
        
        if is_contact_form and not has_captcha:
            forms_without_captcha.append("Contact Form")
    
    if forms_without_captcha:
        findings.append({
            "type": "missing_captcha",
            "area": "Authentication",
            "severity": "medium",
            "message": "❌ CAPTCHA protection missing on critical forms",
            "description": f"Forms without CAPTCHA: {', '.join(forms_without_captcha)}",
            "recommendation": "Implement CAPTCHA on all authentication and contact forms",
            "affected_host": base_domain,
            "vulnerable_component": "Authentication System",
            "evidence": f"Found {len(forms_without_captcha)} forms without CAPTCHA protection"
        })
    else:
        # Check if CAPTCHA is properly implemented
        has_captcha_script = any(indicator in content.lower() for indicator in captcha_indicators)
        if has_captcha_script:
            findings.append({
                "type": "captcha_implemented",
                "area": "Authentication",
                "severity": "info",
                "message": "✅ CAPTCHA protection detected",
                "description": "CAPTCHA mechanism found on forms",
                "recommendation": "Ensure CAPTCHA is properly configured and validated server-side",
                "affected_host": base_domain,
                "vulnerable_component": "Authentication System",
                "evidence": "CAPTCHA scripts detected in page source"
            })
    
    return findings

def check_ip_access(url):
    """Check if website is accessible via IP address"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Get IP address
        ip = socket.gethostbyname(domain)
        
        # Try accessing via IP
        ip_url = f"{parsed.scheme}://{ip}{parsed.path if parsed.path else ''}"
        response = requests.get(ip_url, timeout=5, allow_redirects=False)
        
        return {
            "accessible": response.status_code < 400,
            "ip": ip
        }
    except:
        return {"accessible": False, "ip": None}

def analyze_source_code(content, url, base_domain):
    """Analyze source code for exposed secrets with specific component identification"""
    findings = []
    
    # API Keys patterns with component mapping
    api_key_patterns = {
        'aws_access_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'component': 'AWS Configuration/Environment Variables',
            'file_likely': 'config.py, .env, server.js, application.properties'
        },
        'aws_secret_key': {
            'pattern': r'[0-9a-zA-Z/+]{40}',
            'component': 'AWS Configuration/Environment Variables', 
            'file_likely': 'config.py, .env, credentials file'
        },
        'google_api_key': {
            'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
            'component': 'Google Services Configuration',
            'file_likely': 'config.js, .env, app settings'
        },
        'google_oauth': {
            'pattern': r'ya29\\.[0-9A-Za-z\\-_]+',
            'component': 'OAuth Configuration',
            'file_likely': 'auth.py, oauth config files'
        },
        'facebook_access_token': {
            'pattern': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'component': 'Social Media Integration',
            'file_likely': 'social_auth.py, config files'
        },
        'github_token': {
            'pattern': r'ghp_[0-9a-zA-Z]{36}',
            'component': 'GitHub Integration',
            'file_likely': 'ci_cd config, deployment scripts'
        },
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
            'component': 'Slack Integration',
            'file_likely': 'slack_bot.py, notification config'
        },
        'stripe_key': {
            'pattern': r'sk_live_[0-9a-zA-Z]{24}',
            'component': 'Payment Processing',
            'file_likely': 'payment.py, billing config'
        },
    }
    
    for key_type, key_info in api_key_patterns.items():
        pattern = key_info['pattern']
        component = key_info['component']
        likely_files = key_info['file_likely']
        
        matches = re.findall(pattern, content)
        if matches:
            findings.append({
                "type": "exposed_secret",
                "area": "Information Disclosure",
                "severity": "critical",
                "message": f"❌ {key_type.replace('_', ' ').title()} exposed",
                "description": f"Found {len(matches)} instance(s) of potential {key_type} in client-side code",
                "recommendation": f"Immediately rotate the exposed keys and move to server-side environment variables",
                "affected_host": base_domain,
                "vulnerable_component": component,
                "evidence": f"Found in: {likely_files} - {len(matches)} matches detected"
            })

    # Check for hardcoded credentials in JavaScript with file identification
    js_credentials = re.findall(r'[Pp]assword\s*[=:]\s*[\'"]([^\'"]+)[\'"]', content)
    if js_credentials:
        findings.append({
            "type": "hardcoded_credentials",
            "area": "Authentication",
            "severity": "high",
            "message": "❌ Hardcoded credentials in source code",
            "description": f"Found {len(js_credentials)} potential password assignments in client-side code",
            "recommendation": "Remove hardcoded credentials and use environment variables or secure configuration",
            "affected_host": base_domain,
            "vulnerable_component": "Authentication Configuration",
            "evidence": f"Found in: JavaScript files, config scripts - {len(js_credentials)} hardcoded passwords"
        })

    # Database connection strings
    db_patterns = {
        'mysql_connection': r'mysql://[^"\']+:[^"\']+@[^"\']+',
        'postgres_connection': r'postgresql://[^"\']+:[^"\']+@[^"\']+',
        'mongodb_connection': r'mongodb://[^"\']+:[^"\']+@[^"\']+',
    }
    
    for db_type, pattern in db_patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            findings.append({
                "type": "exposed_database",
                "area": "Information Disclosure",
                "severity": "critical",
                "message": f"❌ {db_type.replace('_', ' ').title()} exposed",
                "description": f"Database connection string exposed in client-side code",
                "recommendation": "Immediately change database credentials and move connection strings to server-side",
                "affected_host": base_domain,
                "vulnerable_component": "Database Configuration",
                "evidence": f"Found in: config files, application code - Database credentials exposed"
            })

    return findings

def analyze_jwt_tokens(headers, base_domain):
    """Analyze JWT tokens in cookies and headers"""
    findings = []
    
    # Check cookies for JWT tokens
    cookie_header = headers.get('set-cookie', '')
    jwt_pattern = r'[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
    
    jwt_matches = re.findall(jwt_pattern, cookie_header)
    for jwt in jwt_matches:
        try:
            # Try to decode JWT without verification
            parts = jwt.split('.')
            if len(parts) == 3:
                header = json.loads(base64.b64decode(parts[0] + '==').decode('utf-8'))
                payload = json.loads(base64.b64decode(parts[1] + '==').decode('utf-8'))
                
                # Check for common JWT issues
                alg = header.get('alg', 'unknown')
                if alg == 'none':
                    findings.append({
                        "type": "jwt_weak_algorithm",
                        "area": "Authentication",
                        "severity": "high",
                        "message": "❌ JWT using 'none' algorithm",
                        "description": "JWT token allows unsigned tokens (none algorithm)",
                        "recommendation": "Use strong signing algorithms like RS256 and implement proper token validation",
                        "affected_host": base_domain,
                        "vulnerable_component": "JWT Authentication Module",
                        "evidence": f"JWT with 'none' algorithm found in cookies - Vulnerable: auth middleware"
                    })
                
                findings.append({
                    "type": "jwt_analysis",
                    "area": "Authentication",
                    "severity": "info",
                    "message": "🔐 JWT Token found and analyzed",
                    "description": f"Algorithm: {alg}, Exp: {payload.get('exp', 'Not set')}",
                    "recommendation": "Ensure proper JWT validation, expiration, and signature verification",
                    "affected_host": base_domain,
                    "vulnerable_component": "JWT Authentication Module", 
                    "evidence": f"JWT token found with algorithm: {alg} - Check: auth controllers"
                })
        except:
            findings.append({
                "type": "jwt_analysis",
                "area": "Authentication",
                "severity": "low",
                "message": "⚠️ JWT-like token found (cannot decode)",
                "description": "Token format detected but cannot be decoded",
                "recommendation": "Verify token structure and encoding in authentication middleware",
                "affected_host": base_domain,
                "vulnerable_component": "JWT Authentication Module",
                "evidence": "JWT-like token pattern found in cookies - Check: token validation logic"
            })
    
    return findings

def find_private_ips(content):
    """Find private IP addresses in source code"""
    private_ip_patterns = [
        r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        r'192\.168\.\d{1,3}\.\d{1,3}',
        r'172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}',
        r'127\.0\.0\.1',
        r'localhost'
    ]
    
    found_ips = []
    for pattern in private_ip_patterns:
        matches = re.findall(pattern, content)
        found_ips.extend(matches)
    
    return list(set(found_ips))

def check_directory_listing(url, base_domain):
    """Check for directory listing vulnerability"""
    findings = []
    test_paths = [
        ('/images/', 'Static Assets Directory'),
        ('/css/', 'Stylesheets Directory'), 
        ('/js/', 'JavaScript Directory'),
        ('/uploads/', 'File Upload Directory'),
        ('/admin/', 'Admin Panel Directory'),
        ('/static/', 'Static Files Directory'),
        ('/assets/', 'Assets Directory'),
        ('/backup/', 'Backup Directory'),
        ('/tmp/', 'Temporary Files Directory')
    ]
    
    for path, component in test_paths:
        try:
            test_url = urljoin(url, path)
            response = requests.get(test_url, timeout=5)
            
            # Check for directory listing indicators
            if any(indicator in response.text.lower() for indicator in 
                  ['index of /', 'directory listing', '<title>directory of']):
                findings.append({
                    "type": "directory_listing",
                    "area": "Server Configuration",
                    "severity": "medium",
                    "message": f"❌ Directory listing enabled",
                    "description": f"Directory listing vulnerability found at {path}",
                    "recommendation": "Disable directory listing in web server configuration",
                    "affected_host": base_domain,
                    "vulnerable_component": component,
                    "evidence": f"Directory listing detected at: {test_url}"
                })
        except:
            continue
    
    return findings

def check_backup_files(url, base_domain):
    """Check for common backup files with component identification"""
    findings = []
    
    backup_files = [
        ('.bak', 'Configuration Backup'),
        ('.backup', 'Application Backup'),
        ('.old', 'Old Version Files'),
        ('.tmp', 'Temporary Files'),
        ('.swp', 'Editor Swap Files'),
        ('.save', 'Saved Files'),
        ('.tar.gz', 'Archive Files'),
        ('.zip', 'Compressed Backup'),
        ('web.config.bak', 'IIS Configuration Backup'),
        ('.env.backup', 'Environment Backup'),
        ('database.sql.bak', 'Database Backup'),
        ('config.php.bak', 'PHP Config Backup')
    ]
    
    for file_ext, component in backup_files:
        try:
            if file_ext.startswith('.'):
                test_url = url.rstrip('/') + file_ext
            else:
                test_url = urljoin(url, file_ext)
                
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                findings.append({
                    "type": "backup_files",
                    "area": "Information Disclosure",
                    "severity": "high",
                    "message": f"❌ Backup file found: {test_url.split('/')[-1]}",
                    "description": f"Backup file accessible at {test_url}",
                    "recommendation": "Remove backup files from web-accessible directories and implement proper backup procedures",
                    "affected_host": base_domain,
                    "vulnerable_component": component,
                    "evidence": f"Backup file accessible: {test_url}"
                })
        except:
            continue
    
    return findings

def detect_sql_errors(content):
    """Detect SQL error messages in response"""
    sql_error_indicators = [
        'sql syntax', 'mysql_fetch', 'ora-', 'postgresql',
        'microsoft odbc', 'driver for sql', 'sqlserver',
        'unclosed quotation mark', 'invalid query'
    ]
    
    content_lower = content.lower()
    return any(error in content_lower for error in sql_error_indicators)

def check_clickjacking(headers):
    """Check for clickjacking protection"""
    x_frame_options = headers.get('x-frame-options', '').lower()
    csp = headers.get('content-security-policy', '').lower()
    
    has_xfo = x_frame_options in ['deny', 'sameorigin']
    has_csp_frame = 'frame-ancestors' in csp and 'none' in csp
    
    return has_xfo or has_csp_frame

def check_ssl_issues(url):
    """Basic SSL/TLS check"""
    try:
        if url.startswith('http:'):
            return "Website using HTTP instead of HTTPS"
        
        # Check for mixed content
        response = requests.get(url, timeout=5)
        if 'http:' in response.text and url.startswith('https:'):
            return "Mixed content detected (HTTP resources loaded over HTTPS)"
            
    except requests.exceptions.SSLError as e:
        return f"SSL certificate error: {str(e)}"
    
    return None

def check_security_headers(headers, base_domain):
    """Check for missing security headers"""
    findings = []
    security_headers = {
        'strict-transport-security': {
            'name': 'HSTS Header',
            'component': 'HTTP Security Headers'
        },
        'content-security-policy': {
            'name': 'Content Security Policy', 
            'component': 'Content Security Configuration'
        },
        'x-frame-options': {
            'name': 'Clickjacking Protection',
            'component': 'Frame Security Headers'
        },
        'x-content-type-options': {
            'name': 'MIME Sniffing Protection',
            'component': 'Content Type Security'
        },
        'referrer-policy': {
            'name': 'Referrer Policy',
            'component': 'Referrer Security Headers'
        },
        'permissions-policy': {
            'name': 'Permissions Policy',
            'component': 'Browser Features Security'
        }
    }
    
    for header, info in security_headers.items():
        if header not in headers:
            findings.append({
                "type": "missing_security_header",
                "area": "Client Security",
                "severity": "medium",
                "message": f"⚠️ {info['name']} missing",
                "description": f"Security header {header} is not present",
                "recommendation": f"Implement {header} security header in web server configuration",
                "affected_host": base_domain,
                "vulnerable_component": info['component'],
                "evidence": f"Missing {header} header in HTTP response - Check: server config files"
            })
    
    return findings

def check_common_subdomains(base_domain):
    """Check for common subdomains"""
    findings = []
    common_subdomains = [
        ('www', 'WWW Subdomain'),
        ('api', 'API Gateway'),
        ('admin', 'Admin Panel'),
        ('test', 'Testing Environment'),
        ('dev', 'Development Environment'),
        ('staging', 'Staging Environment'),
        ('mail', 'Mail Server'),
        ('ftp', 'FTP Server'),
        ('cpanel', 'Control Panel'),
        ('webmail', 'Web Mail Interface')
    ]
    
    for subdomain, component in common_subdomains:
        test_domain = f"{subdomain}.{base_domain}"
        try:
            socket.gethostbyname(test_domain)
            findings.append({
                "type": "subdomain_discovery",
                "area": "Information Disclosure",
                "severity": "info",
                "message": f"🌐 Subdomain found: {test_domain}",
                "description": f"Active subdomain discovered: {test_domain}",
                "recommendation": "Ensure all subdomains are properly secured and implement subdomain monitoring",
                "affected_host": test_domain,
                "vulnerable_component": component,
                "evidence": f"DNS resolution successful for {test_domain}"
            })
        except:
            continue
    
    return findings

def check_server_version_disclosure(headers, base_domain):
    """Check for server version disclosure"""
    findings = []
    
    server_header = headers.get('server', '')
    x_powered_by = headers.get('x-powered-by', '')
    
    # Server version disclosure
    if server_header and any(ch.isdigit() for ch in server_header):
        findings.append({
            "type": "server_version_disclosure",
            "area": "Information Disclosure", 
            "severity": "medium",
            "message": "❌ Server version exposed",
            "description": f"Server version information disclosed: {server_header}",
            "recommendation": "Remove or obfuscate server version information from headers",
            "affected_host": base_domain,
            "vulnerable_component": "Web Server Configuration",
            "evidence": f"Server header exposes version: {server_header}"
        })
    
    # Framework version disclosure
    if x_powered_by and any(ch.isdigit() for ch in x_powered_by):
        findings.append({
            "type": "framework_version_disclosure",
            "area": "Information Disclosure",
            "severity": "medium", 
            "message": "❌ Framework version exposed",
            "description": f"Framework version information disclosed: {x_powered_by}",
            "recommendation": "Remove X-Powered-By header or obfuscate framework information",
            "affected_host": base_domain,
            "vulnerable_component": "Application Framework",
            "evidence": f"X-Powered-By header exposes version: {x_powered_by}"
        })
    
    return findings

def detect_frameworks(content, headers, base_domain):
    """Detect web frameworks and technologies"""
    findings = []
    
    framework_indicators = {
        'React': ['react', 'react-dom', '__reactInternalInstance'],
        'Angular': ['ng-', 'angular', 'zone.js'],
        'Vue.js': ['vue', '__vue__'],
        'jQuery': ['jquery', '$().jquery'],
        'Django': ['csrftoken', 'django'],
        'Laravel': ['laravel', 'csrf-token'],
        'WordPress': ['wp-', 'wordpress', 'xmlrpc.php'],
        'Express.js': ['express', 'x-powered-by: express'],
        'Spring Boot': ['spring', 'x-application-context']
    }
    
    detected_frameworks = []
    content_lower = content.lower()
    
    for framework, indicators in framework_indicators.items():
        for indicator in indicators:
            if indicator.lower() in content_lower or indicator.lower() in str(headers).lower():
                detected_frameworks.append(framework)
                break
    
    if detected_frameworks:
        findings.append({
            "type": "framework_detection",
            "area": "Information Disclosure",
            "severity": "info",
            "message": f"🔧 Technologies detected: {', '.join(set(detected_frameworks))}",
            "description": "Web frameworks and technologies identified",
            "recommendation": "Keep all frameworks and dependencies updated to latest secure versions",
            "affected_host": base_domain,
            "vulnerable_component": "Web Application Stack",
            "evidence": f"Detected frameworks: {', '.join(set(detected_frameworks))}"
        })
    
    return findings

if __name__ == "__main__":
    os.makedirs("static", exist_ok=True)
    print("🚀 Running on http://127.0.0.1:5000")
    app.run(debug=True)
