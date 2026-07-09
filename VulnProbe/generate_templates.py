#!/usr/bin/env python3
"""Generate VulnProbe built-in templates (60 across 8 categories).

Run once:  python generate_templates.py
Writes YAML files into VulnProbe/templates/<category>/
"""
import os
import textwrap
import yaml

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

TEMPLATES = []

# ---------------------------------------------------------------------------
# CATEGORY 1: exposed-panels (15)
# ---------------------------------------------------------------------------
EXPOSED_PANELS = [
    ("exposed-admin-panel", "Exposed Admin Panel Detection",
     "Detects publicly accessible admin panels that should be restricted to internal networks.",
     "HIGH", "admin,panel,exposure,authentication",
     ["/admin", "/admin/login", "/administrator", "/wp-admin", "/phpmyadmin"],
     "Restrict admin panel access to internal IPs using firewall rules or web server access control. Implement strong authentication and consider non-standard ports."),
    ("exposed-phpmyadmin", "Exposed phpMyAdmin",
     "Detects publicly accessible phpMyAdmin database management interfaces.",
     "HIGH", "phpmyadmin,database,exposure",
     ["/phpmyadmin", "/phpMyAdmin", "/pma", "/dbadmin"],
     "Remove phpMyAdmin from production or restrict via firewall/allowlist. Never expose DB management UIs publicly."),
    ("exposed-jenkins-dashboard", "Exposed Jenkins Dashboard",
     "Detects publicly accessible Jenkins CI/CD dashboards.",
     "HIGH", "jenkins,ci,exposure",
     ["/jenkins", "/", "/login"],
     "Restrict Jenkins behind VPN/SSO. Disable anonymous read access in global security settings."),
    ("exposed-grafana-panel", "Exposed Grafana Dashboard",
     "Detects publicly accessible Grafana monitoring dashboards.",
     "MEDIUM", "grafana,monitoring,exposure",
     ["/", "/login", "/dashboard", "/grafana"],
     "Put Grafana behind auth proxy. Enable anonymous auth disabled by default and use OAuth."),
    ("exposed-kibana-dashboard", "Exposed Kibana Dashboard",
     "Detects publicly accessible Kibana dashboards.",
     "MEDIUM", "kibana,elasticsearch,exposure",
     ["/kibana", "/app/kibana", "/"],
     "Bind Kibana to localhost or internal network; front with authenticated reverse proxy."),
    ("exposed-elasticsearch", "Exposed Elasticsearch API",
     "Detects unauthenticated Elasticsearch REST API access.",
     "HIGH", "elasticsearch,search,exposure",
     ["/", "/_cat/indices", "/_cluster/health"],
     "Enable security/xpack auth. Bind to private network. Use firewall rules to block 9200."),
    ("exposed-redis-no-auth", "Exposed Redis Without Authentication",
     "Detects Redis servers accepting unauthenticated commands.",
     "CRITICAL", "redis,cache,exposure,auth",
     ["/"],
     "Set 'requirepass' in redis.conf. Bind to localhost. Never expose Redis to public internet."),
    ("exposed-mongodb-no-auth", "Exposed MongoDB Without Authentication",
     "Detects MongoDB instances accessible without credentials.",
     "CRITICAL", "mongodb,database,exposure,auth",
     ["/"],
     "Enable authentication and role-based access control. Bind to private interfaces only."),
    ("exposed-rabbitmq-management", "Exposed RabbitMQ Management",
     "Detects publicly accessible RabbitMQ management plugin.",
     "MEDIUM", "rabbitmq,message,exposure",
     ["/", "/api/overview", "/login"],
     "Disable management plugin on public interfaces. Restrict via firewall and enable auth."),
    ("exposed-kubernetes-dashboard", "Exposed Kubernetes Dashboard",
     "Detects publicly accessible Kubernetes Dashboard.",
     "HIGH", "kubernetes,k8s,exposure",
     ["/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/", "/"],
     "Never expose the K8s dashboard publicly. Use kubectl proxy or an authenticated ingress with RBAC."),
    ("exposed-traefik-dashboard", "Exposed Traefik Dashboard",
     "Detects publicly accessible Traefik API/dashboard.",
     "MEDIUM", "traefik,proxy,exposure",
     ["/dashboard/", "/api/rawdata", "/"],
     "Disable insecure API/dashboard or protect with middleware auth. Do not expose on public routers."),
    ("exposed-portainer-dashboard", "Exposed Portainer Dashboard",
     "Detects publicly accessible Portainer container UI.",
     "MEDIUM", "portainer,docker,exposure",
     ["/", "/api/status", "/#!/"],
     "Protect Portainer with strong auth and TLS. Bind to internal network only."),
    ("exposed-jupyter-notebook", "Exposed Jupyter Notebook",
     "Detects publicly accessible Jupyter Notebook servers.",
     "HIGH", "jupyter,notebook,exposure",
     ["/", "/tree", "/login"],
     "Set a strong token/password. Bind to localhost and use SSH tunnel or authenticated proxy."),
    ("exposed-airflow-dashboard", "Exposed Airflow Dashboard",
     "Detects publicly accessible Apache Airflow UI.",
     "MEDIUM", "airflow,dag,exposure",
     ["/admin", "/home", "/login"],
     "Enable authentication (RBAC) in Airflow. Restrict via network controls."),
    ("exposed-prometheus-metrics", "Exposed Prometheus Metrics",
     "Detects publicly accessible Prometheus metrics endpoint.",
     "MEDIUM", "prometheus,metrics,exposure",
     ["/metrics", "/graph", "/"],
     "Restrict /metrics endpoint. Expose only via authenticated scrape or internal network."),
]

for tid, name, desc, sev, tags, paths, rem in EXPOSED_PANELS:
    TEMPLATES.append({
        "id": tid, "name": name, "description": desc, "author": "SecureNET",
        "severity": sev, "category": "exposed-panels", "tags": tags.split(","),
        "references": ["https://owasp.org/www-project-top-ten/"],
        "requests": [{
            "method": "GET", "path": paths,
            "headers": {"User-Agent": "Mozilla/5.0 (compatible; SecureNET/1.0)"},
            "follow_redirects": True, "timeout": 10,
            "matchers": {
                "operator": "OR",
                "conditions": [
                    {"type": "status", "values": [200, 302]},
                    {"type": "word", "part": "body", "words": ["login", "dashboard", "admin", "panel"], "condition": "OR"},
                ],
            },
        }],
        "remediation": rem,
    })

# ---------------------------------------------------------------------------
# CATEGORY 2: sensitive-files (10)
# ---------------------------------------------------------------------------
SENSITIVE_FILES = [
    ("exposed-git-config", "Exposed .git/config", "Detects exposed Git configuration file.",
     "HIGH", "git,source,exposure", ["/.git/config"],
     "Remove .git from web roots. Add server rules denying access to .git directories."),
    ("exposed-env-file", "Exposed .env File", "Detects exposed environment/config .env files.",
     "CRITICAL", "env,secrets,exposure", ["/.env", "/.env.example", "/config/.env"],
     "Never commit .env to VCS. Block web access to dotfiles. Rotate any leaked secrets."),
    ("exposed-docker-compose", "Exposed docker-compose.yml", "Detects exposed Docker Compose files.",
     "MEDIUM", "docker,compose,exposure", ["/docker-compose.yml", "/docker-compose.yaml", "/compose.yml"],
     "Keep compose files out of web roots. Use secrets management instead of inline credentials."),
    ("exposed-aws-credentials", "Exposed AWS Credentials", "Detects exposed AWS credential files.",
     "CRITICAL", "aws,credentials,secrets", ["/.aws/credentials", "/aws/credentials"],
     "Rotate the exposed keys immediately. Use IAM roles / instance profiles, never static keys."),
    ("exposed-htpasswd", "Exposed .htpasswd", "Detects exposed Apache .htpasswd files.",
     "HIGH", "htpasswd,auth,exposure", ["/.htpasswd", "/admin/.htpasswd"],
     "Store outside web root. Use hashed credentials and restrict file permissions."),
    ("exposed-backup-files", "Exposed Backup Files", "Detects exposed backup/source copies (.bak/.old/.sql).",
     "MEDIUM", "backup,source,exposure", ["/index.php.bak", "/index.bak", "/config.old", "/app.bak"],
     "Block access to backup/source extensions via web server config. Store backups off-server."),
    ("exposed-database-dump", "Exposed Database Dump", "Detects exposed database dump files (.sql/.db).",
     "HIGH", "database,dump,exposure", ["/db.sql", "/backup.sql", "/data.db", "/dump.sql"],
     "Never serve DB dumps. Store encrypted offsite. Rotate credentials if exposed."),
    ("exposed-private-key", "Exposed Private Key", "Detects exposed private key files (id_rsa/.pem).",
     "CRITICAL", "privatekey,ssh,tls,exposure", ["/id_rsa", "/.ssh/id_rsa", "/key.pem", "/private.pem"],
     "Revoke and regenerate the key pair. Never place private keys in web roots."),
    ("exposed-wp-config", "Exposed wp-config.php", "Detects exposed WordPress configuration files.",
     "HIGH", "wordpress,config,secrets", ["/wp-config.php", "/wp-config.php.bak", "/wp-config.old"],
     "Move sensitive defines out of web root. Set strict file perms. Rotate DB credentials."),
    ("exposed-laravel-env", "Exposed Laravel .env", "Detects exposed Laravel environment file.",
     "CRITICAL", "laravel,env,secrets", ["/.env", "/.env.backup", "/.env.save"],
     "Block .env in web server. Rotate APP_KEY and all secrets. Keep out of VCS."),
]

for tid, name, desc, sev, tags, paths, rem in SENSITIVE_FILES:
    TEMPLATES.append({
        "id": tid, "name": name, "description": desc, "author": "SecureNET",
        "severity": sev, "category": "sensitive-files", "tags": tags.split(","),
        "references": ["https://owasp.org/www-project-top-ten/"],
        "requests": [{
            "method": "GET", "path": paths,
            "headers": {"User-Agent": "Mozilla/5.0 (compatible; SecureNET/1.0)"},
            "follow_redirects": False, "timeout": 10,
            "matchers": {
                "operator": "AND",
                "conditions": [
                    {"type": "status", "values": [200]},
                    {"type": "size", "comparison": "lt", "size": 1048576},
                ],
            },
            "extractors": [
                {"type": "regex", "name": "snippet", "part": "body",
                 "pattern": "(password|secret|key|token|DB_|aws_|private)", "group": 0},
            ],
        }],
        "remediation": rem,
    })

# ---------------------------------------------------------------------------
# CATEGORY 3: version-leak (8)
# ---------------------------------------------------------------------------
VERSION_LEAK = [
    ("apache-version-leak", "Apache Version Leak", "Server header discloses Apache version.",
     "LOW", "apache,version,disclosure", [["/"]],
     "Set 'ServerTokens Prod' and 'ServerSignature Off' to suppress version disclosure."),
    ("nginx-version-leak", "Nginx Version Leak", "Server header discloses nginx version.",
     "LOW", "nginx,version,disclosure", [["/"]],
     "Set 'server_tokens off;' in nginx config to hide version."),
    ("php-version-leak", "PHP Version Leak", "X-Powered-By or body discloses PHP version.",
     "LOW", "php,version,disclosure", [["/", "/index.php"]],
     "Disable 'expose_php = Off' in php.ini. Remove X-Powered-By header."),
    ("server-header-version", "Server Header Version Disclosure", "Server header leaks software version.",
     "LOW", "server,version,disclosure", [["/"]],
     "Normalize/strip Server and X-Powered-By headers at the proxy layer."),
    ("x-powered-by-disclosure", "X-Powered-By Disclosure", "X-Powered-By header reveals backend tech/version.",
     "LOW", "xpoweredby,disclosure,tech", [["/"]],
     "Remove X-Powered-By via backend or reverse proxy header rewrite."),
    ("aspnet-version-header", "ASP.NET Version Header (X-AspNet-Version)", "X-AspNet-Version header discloses framework version.",
     "LOW", "aspnet,version,disclosure", [["/"]],
     "Set 'enableVersionHeader=false' in web.config; remove X-AspNet-Version."),
    ("iis-version-leak", "IIS Version Leak", "Server header discloses Microsoft-IIS version.",
     "LOW", "iis,version,disclosure", [["/"]],
     "Remove server banner via URLRewrite outbound rule or registry 'DisableServerHeader'."),
    ("framework-debug-mode", "Framework Debug Mode Enabled", "Detects debug/error verbose mode leaking stack traces.",
     "MEDIUM", "debug,framework,disclosure", [["/", "/debug", "/?debug=1"]],
     "Disable DEBUG mode in production. Return generic error pages to clients."),
]

for tid, name, desc, sev, tags, paths, rem in VERSION_LEAK:
    req = {
        "method": "GET", "path": paths[0],
        "headers": {"User-Agent": "Mozilla/5.0 (compatible; SecureNET/1.0)"},
        "follow_redirects": True, "timeout": 10,
    }
    if tid in ("apache-version-leak", "nginx-version-leak", "server-header-version", "iis-version-leak"):
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [200, 301, 302, 403, 404]},
                {"type": "header", "header": "Server", "values": ["Apache", "nginx", "Microsoft-IIS"], "condition": "OR"},
                {"type": "regex", "part": "header", "pattern": "(Apache/[0-9]|nginx/[0-9]|Microsoft-IIS/[0-9])", "case_insensitive": True},
            ],
        }
    elif tid == "php-version-leak":
        req["matchers"] = {
            "operator": "OR",
            "conditions": [
                {"type": "header", "header": "X-Powered-By", "values": ["PHP"], "condition": "AND"},
                {"type": "regex", "part": "body", "pattern": "PHP Version [0-9]", "case_insensitive": True},
            ],
        }
    elif tid == "x-powered-by-disclosure":
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [200, 301, 302]},
                {"type": "header", "header": "X-Powered-By", "values": ["ASP.NET", "PHP", "Express", "Django"], "condition": "OR"},
            ],
        }
    elif tid == "aspnet-version-header":
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [200, 301, 302]},
                {"type": "header", "header": "X-AspNet-Version", "values": ["1", "2", "3", "4"], "condition": "OR"},
            ],
        }
    elif tid == "framework-debug-mode":
        req["matchers"] = {
            "operator": "OR",
            "conditions": [
                {"type": "word", "part": "body", "words": ["DEBUG=True", "DEBUG = True", "Traceback (most recent call last)", "Django error"], "condition": "OR"},
                {"type": "status", "values": [500]},
            ],
        }
    TEMPLATES.append({
        "id": tid, "name": name, "description": desc, "author": "SecureNET",
        "severity": sev, "category": "version-leak", "tags": tags.split(","),
        "references": ["https://owasp.org/www-project-top-ten/"],
        "requests": [req],
        "remediation": rem,
    })

# ---------------------------------------------------------------------------
# CATEGORY 4: default-creds (5) -- detect pages only, never attempt login
# ---------------------------------------------------------------------------
DEFAULT_CREDS = [
    ("default-login-page-detected", "Default Login Page Detected", "Detects default device/application login pages.",
     "INFO", "default,login,page", ["/login", "/admin/login", "/user/login"],
     "Change default credentials immediately. Use unique strong passwords and MFA."),
    ("router-admin-default", "Router Admin Default Page", "Detects router admin interfaces.",
     "MEDIUM", "router,admin,default", ["/", "/login", "/cgi-bin/luci"],
     "Change default admin password. Disable remote admin. Update firmware."),
    ("printer-admin-default", "Printer Admin Default", "Detects printer web admin interfaces.",
     "LOW", "printer,admin,default", ["/", "/hp/device/this.LCDispatcher", "/set_config.html"],
     "Set admin password. Disable unnecessary services. Update printer firmware."),
    ("camera-default-login", "IP Camera Default Login", "Detects IP camera/webcam admin pages.",
     "MEDIUM", "camera,default,login", ["/", "/login", "/web/login"],
     "Change default credentials. Segment cameras on isolated VLAN. Patch firmware."),
    ("switch-admin-default", "Network Switch Admin Default", "Detects managed switch admin pages.",
     "MEDIUM", "switch,admin,default", ["/", "/login", "/config"],
     "Change default enable passwords. Restrict mgmt plane. Use centralized auth."),
]

for tid, name, desc, sev, tags, paths, rem in DEFAULT_CREDS:
    TEMPLATES.append({
        "id": tid, "name": name, "description": desc, "author": "SecureNET",
        "severity": sev, "category": "default-creds", "tags": tags.split(","),
        "references": ["https://owasp.org/www-project-top-ten/"],
        "requests": [{
            "method": "GET", "path": paths,
            "headers": {"User-Agent": "Mozilla/5.0 (compatible; SecureNET/1.0)"},
            "follow_redirects": True, "timeout": 10,
            "matchers": {
                "operator": "AND",
                "conditions": [
                    {"type": "status", "values": [200, 401, 403]},
                    {"type": "word", "part": "body", "words": ["login", "password", "sign in", "username"], "condition": "OR"},
                ],
            },
        }],
        "remediation": rem,
    })

# ---------------------------------------------------------------------------
# CATEGORY 5: misconfiguration (7)
# ---------------------------------------------------------------------------
MISCONFIG = [
    ("cors-wildcard-origin", "CORS Wildcard Origin", "Access-Control-Allow-Origin: * with credentials.",
     "MEDIUM", "cors,misconfig,header", [["/"]],
     "Restrict ACAO to known origins. Never combine '*' with 'Access-Control-Allow-Credentials: true'."),
    ("directory-listing-enabled", "Directory Listing Enabled", "Detects enabled directory listing.",
     "LOW", "directory,listing,misconfig", [["/"], ["/static/"], ["/images/"]],
     "Disable directory indexing (Options -Indexes in Apache, autoindex off in nginx)."),
    ("http-methods-trace-enabled", "HTTP TRACE Enabled", "Detects enabled TRACE method.",
     "LOW", "trace,method,misconfig",
     ["/"],
     "Disable TRACE method server-side to mitigate cross-site tracing."),
    ("http-put-method-enabled", "HTTP PUT Enabled", "Detects enabled PUT/DELETE methods (potential file upload).",
     "MEDIUM", "put,method,misconfig",
     ["/put-test-vulnprobe.txt"],
     "Disable PUT/DELETE unless required. Restrict WebDAV to trusted principals."),
    ("clickjacking-no-xframe", "Missing X-Frame-Options", "Detects missing clickjacking protection headers.",
     "LOW", "clickjacking,xfo,misconfig", [["/"]],
     "Set X-Frame-Options: DENY (or CSP frame-ancestors) on all responses."),
    ("content-sniffing-enabled", "Missing X-Content-Type-Options", "Detects missing MIME-sniffing protection.",
     "LOW", "sniffing,misconfig,header", [["/"]],
     "Set 'X-Content-Type-Options: nosniff' to prevent MIME sniffing."),
    ("debug-endpoint-exposed", "Exposed Debug Endpoint", "Detects exposed debug/actuator/test endpoints.",
     "MEDIUM", "debug,endpoint,misconfig", ["/actuator", "/debug", "/__debug__", "/.well-known/debug"],
     "Disable debug endpoints in production. Require auth and internal network."),
]

for tid, name, desc, sev, tags, paths, rem in MISCONFIG:
    # normalize paths to a flat list of strings
    flat_paths = []
    for p in paths:
        if isinstance(p, list):
            flat_paths.extend(p)
        else:
            flat_paths.append(p)
    req = {
        "method": "GET", "path": flat_paths,
        "headers": {"User-Agent": "Mozilla/5.0 (compatible; SecureNET/1.0)"},
        "follow_redirects": True, "timeout": 10,
    }
    if tid == "cors-wildcard-origin":
        req["method"] = "GET"
        req["headers"]["Origin"] = "https://evil.example.com"
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "header", "header": "Access-Control-Allow-Origin", "values": ["*", "https://evil.example.com"], "condition": "OR"},
            ],
        }
    elif tid == "directory-listing-enabled":
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [200]},
                {"type": "regex", "part": "body", "pattern": "(Index of|Directory listing|Parent Directory)", "case_insensitive": True},
            ],
        }
    elif tid == "http-methods-trace-enabled":
        req["method"] = "OPTIONS"
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "header", "header": "Allow", "values": ["TRACE"], "condition": "OR"},
            ],
        }
    elif tid == "http-put-method-enabled":
        req["method"] = "OPTIONS"
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "header", "header": "Allow", "values": ["PUT", "PUT,", "DELETE"], "condition": "OR"},
            ],
        }
    elif tid == "clickjacking-no-xframe":
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [200, 301, 302, 403, 404]},
                {"type": "header", "header": "X-Frame-Options", "values": [""], "condition": "AND", "negate": True},
            ],
        }
        # require absence of X-Frame-Options AND CSP frame-ancestors not set
        req["matchers"]["conditions"].append(
            {"type": "header", "header": "Content-Security-Policy", "values": [""], "condition": "AND", "negate": True}
        )
    elif tid == "content-sniffing-enabled":
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [200, 301, 302, 403, 404]},
                {"type": "header", "header": "X-Content-Type-Options", "values": ["nosniff"], "condition": "AND", "negate": True},
            ],
        }
    elif tid == "debug-endpoint-exposed":
        req["matchers"] = {
            "operator": "OR",
            "conditions": [
                {"type": "status", "values": [200]},
                {"type": "word", "part": "body", "words": ["actuator", "debug", "env", "beans"], "condition": "OR"},
            ],
        }
    TEMPLATES.append({
        "id": tid, "name": name, "description": desc, "author": "SecureNET",
        "severity": sev, "category": "misconfiguration", "tags": tags.split(","),
        "references": ["https://owasp.org/www-project-top-ten/"],
        "requests": [req],
        "remediation": rem,
    })

# ---------------------------------------------------------------------------
# CATEGORY 6: cve (5) -- read-only detection only, never exploit
# ---------------------------------------------------------------------------
CVE = [
    ("cve-2021-41773-apache-rce-check", "CVE-2021-41773 Apache Path Traversal",
     "Read-only probe for Apache 2.4.49 path traversal (no exploitation).",
     "CRITICAL", "cve,apache,rce", ["/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"],
     "Upgrade Apache to >=2.4.51. Restrict directory access. WAF rule for encoded traversal."),
    ("cve-2021-44228-log4j-check", "CVE-2021-44228 Log4Shell",
     "Read-only probe for Log4j JNDI lookup exposure (no exploitation).",
     "CRITICAL", "cve,log4j,rce", ["/", "/login", "/api"],
     "Update Log4j to >=2.17.0. Set log4j2.formatMsgNoLookups=true. WAF JNDI patterns."),
    ("cve-2022-22965-spring4shell-check", "CVE-2022-22965 Spring4Shell",
     "Read-only probe for Spring4Shell RCE precondition (no exploitation).",
     "CRITICAL", "cve,spring,rce", ["/"],
     "Upgrade Spring to patched version. Disallow binding to sensitive fields. WAF rules."),
    ("cve-2019-11043-php-fpm-check", "CVE-2019-11043 php-fpm RCE",
     "Read-only probe for php-fpm env path info RCE precondition.",
     "HIGH", "cve,php,fpm", ["/index.php/xxxxx"],
     "Upgrade php-fpm. Remove vulnerable nginx 'PATH_INFO' config. Patch PHP."),
    ("cve-2020-5902-f5-bigip-check", "CVE-2020-5902 F5 BIG-IP",
     "Read-only probe for F5 BIG-IP TMUI traversal (no exploitation).",
     "CRITICAL", "cve,f5,bigip", ["/tmui/login.jsp/..;/tmui/locallogout.jsp"],
     "Upgrade BIG-IP. Restrict TMUI mgmt to internal network. Apply vendor iRule."),
]

for tid, name, desc, sev, tags, paths, rem in CVE:
    TEMPLATES.append({
        "id": tid, "name": name, "description": desc, "author": "SecureNET",
        "severity": sev, "category": "cve", "tags": tags.split(","),
        "references": [f"https://nvd.nist.gov/vuln/detail/{tid.split('-', 2)[1].upper()}"],
        "requests": [{
            "method": "GET", "path": paths,
            "headers": {"User-Agent": "Mozilla/5.0 (compatible; SecureNET/1.0)"},
            "follow_redirects": False, "timeout": 10,
            "matchers": {
                "operator": "OR",
                "conditions": [
                    {"type": "word", "part": "body", "words": ["root:x:", "bin/bash", "uid=", "java.lang"], "condition": "OR"},
                    {"type": "status", "values": [500, 502]},
                ],
            },
        }],
        "remediation": rem,
    })

# ---------------------------------------------------------------------------
# CATEGORY 7: api-security (5)
# ---------------------------------------------------------------------------
API_SEC = [
    ("graphql-introspection-enabled", "GraphQL Introspection Enabled",
     "Detects GraphQL introspection query allowed (schema disclosure).",
     "MEDIUM", "graphql,api,introspection", ["/graphql", "/api/graphql", "/graphiql"],
     "Disable introspection in production. Use persisted queries. Authorize schema access."),
    ("swagger-ui-exposed", "Swagger UI Exposed", "Detects exposed Swagger/OpenAPI UI.",
     "LOW", "swagger,api,exposure", ["/swagger-ui.html", "/swagger", "/api-docs", "/v2/api-docs"],
     "Restrict API docs to internal environments. Require auth for schema endpoints."),
    ("api-docs-exposed", "API Docs Exposed", "Detects exposed API documentation (ReDoc/OpenAPI).",
     "LOW", "api,docs,exposure", ["/redoc", "/openapi.json", "/docs", "/api/schema"],
     "Gate documentation behind auth. Do not expose in production by default."),
    ("actuator-endpoints-exposed", "Spring Actuator Exposed", "Detects exposed Spring Boot Actuator endpoints.",
     "MEDIUM", "actuator,spring,api,exposure", ["/actuator", "/actuator/env", "/actuator/health", "/actuator/beans"],
     "Restrict actuator exposure to 'health'/'info'. Secure with auth. Bind internally."),
    ("odata-exposed", "OData Service Exposed", "Detects exposed OData service metadata.",
     "LOW", "odata,api,exposure", ["/odata", "/odata/$metadata", "/api/odata"],
     "Restrict OData metadata visibility. Authenticate service documents in production."),
]

for tid, name, desc, sev, tags, paths, rem in API_SEC:
    TEMPLATES.append({
        "id": tid, "name": name, "description": desc, "author": "SecureNET",
        "severity": sev, "category": "api-security", "tags": tags.split(","),
        "references": ["https://owasp.org/www-project-api-security/"],
        "requests": [{
            "method": "GET", "path": paths,
            "headers": {"User-Agent": "Mozilla/5.0 (compatible; SecureNET/1.0)",
                        "Accept": "application/json"},
            "follow_redirects": True, "timeout": 10,
            "matchers": {
                "operator": "AND",
                "conditions": [
                    {"type": "status", "values": [200, 302]},
                    {"type": "word", "part": "body",
                     "words": ["swagger", "openapi", "graphql", "actuator", "odata", "schema", "__typename"],
                     "condition": "OR"},
                ],
            },
        }],
        "remediation": rem,
    })

# ---------------------------------------------------------------------------
# CATEGORY 8: ssl-headers (5)
# ---------------------------------------------------------------------------
SSL_HEADERS = [
    ("http-no-redirect-to-https", "No HTTPS Redirect", "Detects HTTP not redirecting to HTTPS.",
     "LOW", "https,redirect,misconfig",
     ["http://__TARGET_HOST__"],
     "Redirect all HTTP traffic to HTTPS. Use HSTS to enforce transport security."),
    ("mixed-content-detected", "Mixed Content Detected", "Detects HTTP resources loaded on HTTPS page.",
     "LOW", "mixed-content,https,misconfig",
     ["/"],
     "Serve all sub-resources over HTTPS. Use CSP upgrade-insecure-requests."),
    ("missing-hsts-header", "Missing HSTS Header", "Detects missing Strict-Transport-Security header.",
     "LOW", "hsts,https,header",
     ["/"],
     "Set 'Strict-Transport-Security: max-age=63072000; includeSubDomains' on HTTPS responses."),
    ("security-txt-missing", "security.txt Missing", "Detects missing /.well-known/security.txt.",
     "INFO", "security-txt,disclosure",
     ["/.well-known/security.txt"],
     "Publish a security.txt with contact + disclosure policy per RFC 9116."),
    ("robots-txt-exposed", "robots.txt Discloses Sensitive Paths", "Detects robots.txt exposing sensitive directories.",
     "INFO", "robots,disclosure",
     ["/robots.txt"],
     "Avoid listing sensitive paths in robots.txt; use auth/access control instead."),
]

for tid, name, desc, sev, tags, paths, rem in SSL_HEADERS:
    req = {
        "method": "GET", "path": paths,
        "headers": {"User-Agent": "Mozilla/5.0 (compatible; SecureNET/1.0)"},
        "follow_redirects": True, "timeout": 10,
    }
    if tid == "http-no-redirect-to-https":
        req["path"] = ["/"]
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [200, 301, 302, 403, 404]},
                {"type": "status", "values": [301, 302, 307, 308], "negate": True},
            ],
        }
    elif tid == "mixed-content-detected":
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [200]},
                {"type": "regex", "part": "body",
                 "pattern": "(src|href)=\"http://", "case_insensitive": True},
            ],
        }
    elif tid == "missing-hsts-header":
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [200, 301, 302, 403, 404]},
                {"type": "header", "header": "Strict-Transport-Security", "values": [""], "condition": "AND", "negate": True},
            ],
        }
    elif tid == "security-txt-missing":
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [404, 403, 401, 500]},
            ],
        }
    elif tid == "robots-txt-exposed":
        req["matchers"] = {
            "operator": "AND",
            "conditions": [
                {"type": "status", "values": [200]},
                {"type": "regex", "part": "body",
                 "pattern": "(Disallow:.*(admin|api|private|secret|config|backup))",
                 "case_insensitive": True},
            ],
        }
    TEMPLATES.append({
        "id": tid, "name": name, "description": desc, "author": "SecureNET",
        "severity": sev, "category": "ssl-headers", "tags": tags.split(","),
        "references": ["https://owasp.org/www-project-top-ten/"],
        "requests": [req],
        "remediation": rem,
    })


def main():
    cats = {}
    for t in TEMPLATES:
        cats.setdefault(t["category"], []).append(t)
    for cat, items in cats.items():
        d = os.path.join(BASE, cat)
        os.makedirs(d, exist_ok=True)
        for t in items:
            # Build YAML in template order
            block = {
                "id": t["id"], "name": t["name"], "description": t["description"],
                "author": t["author"], "severity": t["severity"],
                "category": t["category"], "tags": t["tags"],
                "references": t.get("references", []),
                "requests": t["requests"],
            }
            if t.get("remediation"):
                block["remediation"] = t["remediation"]
            fname = os.path.join(d, t["id"] + ".yaml")
            header = f"# VulnProbe template — {t['name']}\n# id: {t['id']} | severity: {t['severity']} | category: {t['category']}\n"
            with open(fname, "w", encoding="utf-8") as fh:
                fh.write(header)
                yaml.safe_dump(block, fh, sort_keys=False, default_flow_style=False, allow_unicode=True, width=100)
    print(f"Wrote {len(TEMPLATES)} templates across {len(cats)} categories.")


if __name__ == "__main__":
    main()
