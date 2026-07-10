#!/usr/bin/env python3
"""Generate PathProbe built-in wordlists with exact entry counts.

common.txt  -> 500 entries
api.txt     -> 300 entries
files.txt   -> 200 entries
large.txt   -> 5000 entries (curated + programmatic expansions, deduped)

Run from the PathProbe/ directory.
"""
from __future__ import annotations

import os

HERE = os.path.dirname(os.path.abspath(__file__))
WL = os.path.join(HERE, "wordlists")
os.makedirs(WL, exist_ok=True)

# ---- Curated common web paths (admin/login/static/etc.) ----
COMMON_SEED = """
admin login dashboard backup config uploads images static css js includes
wp-admin wp-content wp-includes wp-login phpmyadmin cgi-bin .git .env robots.txt sitemap.xml
api api/v1 api/v2 api/users api/admin graphql swagger openapi.json api-docs
health metrics status actuator debug console test staging dev development
assets public private secure secret tmp temp cache logs log error
index index.php index.html home default wp-admin admin.php
user users account profile settings preferences
panel manage management cp cpanel whm plesk
db database sql data store
file files download downloads media documents docs
image images img picture pictures photo photos gallery
css style styles stylesheet fonts font
js script scripts app js/app
src source code repo git
about contact help faq support terms privacy policy
search results result query
news blog articles post posts feed rss atom
shop store cart checkout payment pay
forum community chat message messages mail email
calendar events event schedule
report reports analytics stats statistic
server-status server-info balancer-manager
phpinfo info version status
xmlrpc server-status
backup.zip backup.sql backup.tar.gz old.bak
.htaccess .htpasswd web.config
crossdomain.xml clientaccesspolicy.xml
swagger-ui.html swagger-resources
vendor composer.json package.json package-lock.json
yarn.lock bower.json
.env.local .env.dev .env.prod .env.example
config.inc.php configuration settings.inc
readme readme.html readme.md license changelog
install install.php setup upgrade
moderator moderator.php
cms cms/admin sitecore umbraco
joomla joomla administrator
drupal drupal admin
magento magento admin
opencart
gitlab jenkins sonarqube grafana kibana
redis rabbitmq mongodb php redis
elasticsearch kibana
tomcat manager htmlmanager host-manager
axis2
jira confluence bitbucket
wiki dokuwiki mediawiki tikiwiki
roundcube squirrelmail horde
phpbb smf mybb vbulletin
oscommerce prestashop opencart
webmail
mailman
cacti nagios zabbix munin
owncloud nextcloud seafile
piwik matomo
stats awstats webalizer
banner administration administration
mod_status
proxy
gateway
endpoint
v1 v2 v3
oauth oauth2 token auth authorization
callback redirect
export import
upload
delete
edit
view
show
list
add
new
create
remove
reset password forgot
signin signout signup logout
register
portal
intranet extranet
internal
private
hidden
secret
secure
system
sysadmin
root
superuser
webadmin
network
monitor
metrics
tracing
actuator prometheus
graphql playground
ide
vscode
ws
socket
stream
push
notify
notifications
alerts
webhook
cron
task
jobs
queue
worker
batch
service
services
api-key api_keys
keys
credentials
session
sessions
csrf
token tokenize
verify verification
validate
check
ping
echo
hello
info.php php phpmyadmin pma
myadmin
sqlweb
dbweb
adminer
team
member
client
customer
partner
vendor
supplier
order orders
product products
item items
category categories
tag tags
comment comments
rating reviews
wishlist
cart cart.php
payment paypal stripe
invoice invoices
billing
subscription
account account.php
dashboard dashboard.php
control control-panel
panel panel.php
cp cp.php
admincp
mod
modcp
bb
forum forum.php
board
topic topics
thread threads
group groups
role roles
permission permissions
acl
rbac
audit
log logs
error_log
access_log
auth
authenticate
login login.php
logout
session session.php
captcha
2fa mfa otp
sso saml ldap
oauth oauth2
jwt
bearer
xhr
ajax
json
xml
yaml yml
csv
txt
pdf
doc
docx
xls
xlsx
api api.php
rest
soap
wsdl
rpc
graphql graphiql
v1 v2 v3 version versions
beta alpha demo sandbox
staging stage preprod
uat
prod production
live
test testing
qa
hidden hidden.php
secret secret.php
private private.php
internal internal.php
system system.php
shell shell.php
cmd command
exec
run
eval
include includes
require
lib libs library
bin
sbin
etc
var
tmp temp
cache cached
session sessions
upload uploaded
files filemanager
manager file-manager
explorer
browse
dir
directory
folder
list list.php
ls
cat
show
adminer adminer.php
pma pma.php
sql sql.php
db db.php database.php
config config.php configuration.php
settings settings.php options
wp wp-login.php wp-admin
joomla joomla administrator
drupal
magento
opencart
prestashop
webmin
usermin
directadmin
vestacp
froxlor
ispconfig
cyberpanel
aaPanel
bt
""".split()

# ---- Curated API paths ----
API_SEED = """
api api/v1 api/v2 api/v3 api/latest
api/users api/user api/admin api/admins
api/auth api/login api/logout api/token api/oauth api/oauth2 api/jwt
api/register api/signup api/account api/profile api/me
api/health api/status api/metrics api/ping api/version api/info
api/config api/settings api/options
api/search api/query api/filter
api/data api/dataset api/datasets api/export api/import
api/files api/file api/uploads api/download api/media
api/images api/image api/avatar api/photos
api/products api/product api/orders api/order api/cart api/checkout
api/payment api/payments api/invoice api/billing api/subscription
api/comments api/comment api/posts api/post api/articles api/article
api/messages api/message api/chat api/notifications api/notify
api/users/:id api/users/me api/users/search
api/groups api/group api/roles api/role api/permissions
api/keys api/key api/api-keys api/apikey api/api_keys
api/webhooks api/webhook api/callbacks api/callback
api/swagger api/swagger.json api/swagger.yaml api/openapi api/openapi.json api/openapi.yaml
api/docs api/doc api/api-docs api/redoc
api/graphql api/graphql/console api/playground api/graphiql
api/actuator api/actuator/health api/actuator/info api/actuator/env api/actuator/metrics
api/v1/users api/v1/users/:id api/v1/auth api/v1/login
api/v1/admin api/v1/config api/v1/products api/v1/orders
api/v2/users api/v2/auth api/v2/admin api/v2/search
api/internal api/internal/users api/internal/admin api/internal/metrics
api/public api/public/status api/public/health
api/private api/secure api/protected
api/v1/token api/v2/token api/refresh api/refresh-token
api/session api/session/validate api/session/check
api/csrf api/csrf-token
api/reset api/reset-password api/forgot api/forgot-password
api/verify api/verification api/otp api/mfa api/2fa
api/sso api/saml api/ldap api/oidc
api/ws api/websocket api/socket api/stream api/sse
api/events api/event api/webhooks/events
api/tasks api/task api/jobs api/job api/queue api/worker
api/cron api/batch api/bulk
api/report api/reports api/log api/logs api/audit
api/debug api/test api/dev api/staging
api/services api/service api/gateway api/proxy api/router
api/v1/clients api/v1/customer api/v1/partner api/v1/vendor
api/orders/:id api/orders/search api/orders/create
api/products/:id api/products/search api/products/create
api/v1/items api/v1/item api/v1/categories api/v1/tags
api/comments/:id api/v1/comments api/v2/comments
api/upload api/uploads api/v1/upload
api/download api/v1/download api/file/download
api/avatar api/v1/avatar api/user/avatar
api/feed api/rss api/atom api/v1/feed
api/auth/me api/auth/refresh api/auth/logout api/auth/verify
api/admin/users api/admin/config api/admin/metrics api/admin/logs
api/internal/status api/internal/config api/internal/debug
api/v1/auth/login api/v1/auth/token api/v2/auth/login
api/v1/oauth/token api/v1/oauth/authorize
api/v1/graphql api/v2/graphql
api/ping api/v1/ping api/v2/ping
api/credentials api/secrets api/secret api/keys/list
api/zones api/records api/domains api/hosts
api/nodes api/cluster api/instances
api/v1/webhooks api/v2/webhooks api/webhooks/test
api/v1/notifications/read api/v1/notifications/unread
api/v1/messages/send api/v1/messages/inbox
api/metrics/prometheus api/actuator/prometheus
api/healthz api/ready api/readyz api/live api/livez
api/tracing api/trace api/zipkin api/jaeger
"""

# ---- Curated sensitive file paths ----
FILES_SEED = """
.htaccess .htpasswd web.config .env .env.local .env.dev .env.prod .env.example
config.php config.inc.php configuration.php settings.php settings.inc
database.yml database.php database.config db.php db.ini
settings.py settings.pyc settings_local.py
id_rsa id_rsa.pub id_dsa id_ecdsa id_ed25519
authorized_keys known_hosts
config.json config.xml config.yaml config.yml config.ini config.conf
secrets.json secrets.yml credentials.json credentials.yml
.env.backup .env.bak .env.old .env.save
wp-config.php wp-config.bak wp-config.old
configuration.xml app.config application.yml application.properties
application.conf server.xml context.xml web.xml
.env.production .env.staging .env.test
bootstrap.php bootstrap.ini
constants.php defines.php
local.php local.xml local.yml local.json
global.php global.xml global.config
php.ini php.ini-development php.ini-production
user.ini .user.ini
.htusers .htgroups .htaccess.bak
nginx.conf nginx.conf.default
apache2.conf httpd.conf
props.ini props.conf properties.xml
secrets.env secrets.config credentials.env vault.json
connections.json connections.xml datasource.xml
db.sql db.sqlite db.sqlite3 data.sql data.db
database.sql database.sql.gz database.dump
backup.sql backup.sql.gz backup.zip backup.tar.gz backup.bak
old.bak old.zip old.tar.gz old.sql
dump.sql dump.rdb
sitebackup.zip sitebackup.tar.gz
credentials.txt credentials.csv
passwords.txt passwords.json passwd
users.json users.csv users.xml accounts.json
admin.json admin.yml root.txt
token.txt token.json api.key api_keys.json
private.key private.pem server.key server.key.pem
client.key client.pem ca.key ca.pem ca.crt
cert.pem cert.crt fullchain.pem privkey.pem
ssl.key ssl.pem ssl/cert.pem ssl/private.key
secret_token.txt access_token.txt
.env~ .env.swp .env.swo
config~ config.swp
.git/config .git/HEAD .gitignore .svn/entries .svn/wc.db
.bzr/branch/ .hg/store/
.DS_Store desktop.ini Thumbs.db
package.json package-lock.json yarn.lock bower.json composer.lock
composer.json Gemfile Gemfile.lock requirements.txt Pipfile Pipfile.lock
pom.xml build.gradle settings.gradle
webpack.config.js vite.config.js babel.config.js
.travis.yml .gitlab-ci.yml circle.yml appveyor.yml
docker-compose.yml docker-compose.override.yml Dockerfile Makefile
.kube/config kubernetes config
terraform.tfstate terraform.tfvars
ansible.cfg inventory.ini playbook.yml
robots.txt sitemap.xml crossdomain.xml clientaccesspolicy.xml
error.log error_log access.log access_log debug.log
phpinfo.php info.php test.php temp.php tmp.php
phpmyadmin/config.inc.php pma/config.inc.php
console.php shell.php cmd.php command.php
eval.php exec.php run.php system.php
backup.tgz backups.zip backups.tar.gz
db_backup.sql site_backup.zip
old site old version_old
copy.zip copy.tar.gz
sql.bak sql.old mysql.sql mysql.dump
pgsql.sql pg_dump
mongo_dump mongoexport
redis.rdb dump.rdb
secrets.yaml vault.yml ansible-vault
credentials.properties
db_credentials.json
aws_credentials aws.config credentials.aws
.aws/credentials
gcp.json service-account.json
azure.json
firebase.json google-services.json
.keystore keystore.jks truststore.jks
token.key session.key
api_secret api.secret client_secret client.secret
private_key.pem rsa_private.pem
.envrc
secrets.py secrets.pyc
local_settings.py
prod.env
test.py admin_test.php
server-status server-info
"""

COMMON_EXTRA_PREFIX = [
    "admin", "user", "account", "manage", "panel", "control", "config", "setting",
    "system", "secure", "private", "internal", "hidden", "secret", "debug", "test",
    "dev", "staging", "beta", "old", "new", "api", "web", "app", "mobile", "public",
    "static", "assets", "media", "upload", "download", "file", "data", "db",
]
COMMON_EXTRA_SUFFIX = [
    "panel", "console", "interface", "center", "cp", "portal", "area", "zone",
    "manager", "dashboard", "login", "admin", "config", "settings", "status",
    "info", "help", "support", "tools", "util", "api", "service", "handler",
]


def dedup(seq):
    seen = set()
    out = []
    for s in seq:
        s = s.strip().lstrip("/")
        if not s:
            continue
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def build_common():
    words = dedup(COMMON_SEED)
    # expand with prefix/suffix combos until 500
    i = 0
    while len(words) < 500:
        p = COMMON_EXTRA_PREFIX[i % len(COMMON_EXTRA_PREFIX)]
        s = COMMON_EXTRA_SUFFIX[(i // len(COMMON_EXTRA_PREFIX)) % len(COMMON_EXTRA_SUFFIX)]
        i += 1
        cand = f"{p}-{s}" if i % 2 else f"{s}-{p}"
        if cand not in words:
            words.append(cand)
        if i > 5000:
            break
    return words[:500]


def build_api():
    words = dedup(API_SEED.split())
    # version/variant expansion to reach 300
    variants = ["v1", "v2", "v3", "beta", "internal", "public", "private", "legacy"]
    bases = ["users", "auth", "admin", "config", "search", "data", "files", "orders",
             "products", "messages", "notifications", "tasks", "services", "metrics", "health"]
    i = 0
    while len(words) < 300:
        b = bases[i % len(bases)]
        v = variants[(i // len(bases)) % len(variants)]
        i += 1
        cand = f"api/{v}/{b}"
        if cand not in words:
            words.append(cand)
        if i > 3000:
            break
    return words[:300]


def build_files():
    words = dedup(FILES_SEED.split())
    # expand hidden dotfiles
    extras = [f".{c}" for c in ["npmrc", "yarnrc", "gitignore", "dockerignore", "editorconfig",
                                 "eslintrc", "prettierrc", "babelrc", "watchmanconfig",
                                 "metadata", "buildignore", "gitattributes", "npmignore"]]
    for e in extras:
        if e not in words:
            words.append(e)
    i = 0
    while len(words) < 200:
        cand = f"backup_{i:03d}.zip"
        if cand not in words:
            words.append(cand)
        i += 1
    return words[:200]


def build_large():
    base = dedup(COMMON_SEED + API_SEED.split() + FILES_SEED.split())
    # many additional discovery entries
    more = []
    # numeric id paths
    for n in list(range(1, 51)) + [100, 200, 404, 500, 1000]:
        more.append(f"item/{n}")
        more.append(f"user/{n}")
        more.append(f"id/{n}")
        more.append(f"order/{n}")
        more.append(f"post/{n}")
        more.append(f"page/{n}")
        more.append(f"product/{n}")
        more.append(f"comment/{n}")
        more.append(f"api/v1/users/{n}")
        more.append(f"api/v2/items/{n}")
    # year/month blog paths
    for y in range(2018, 2025):
        for m in range(1, 13):
            more.append(f"blog/{y}/{m:02d}")
            more.append(f"news/{y}/{m:02d}")
    # language paths
    for lang in ["en", "es", "fr", "de", "zh", "ru", "ja", "ar", "pt", "it"]:
        more.append(f"{lang}/admin")
        more.append(f"{lang}/login")
        more.append(f"{lang}/api")
        more.append(f"{lang}/home")
        more.append(f"{lang}/index")
    # common extensions on common words
    for w in ["index", "home", "admin", "login", "config", "api", "robots", "sitemap", "main", "default"]:
        for ext in ["php", "html", "htm", "asp", "aspx", "jsp", "json", "xml", "txt", "bak", "old", "sql", "zip", "tar.gz"]:
            more.append(f"{w}.{ext}")
    # subdir traversal patterns
    for d in ["admin", "api", "backup", "config", "user", "system", "static", "assets", "uploads", "images", "css", "js", "private", "secure", "internal"]:
        more.append(f"{d}/index")
        more.append(f"{d}/login")
        more.append(f"{d}/config")
        more.append(f"{d}/list")
        more.append(f"{d}/api")
        more.append(f"{d}/status")
        more.append(f"{d}/.env")
        more.append(f"{d}/backup")
    # application servers / frameworks
    for f in ["laravel", "symfony", "django", "rails", "spring", "express", "flask", "node", "vue", "react", "angular", "next", "nuxt"]:
        more.append(f"{f}/admin")
        more.append(f"{f}/api")
        more.append(f"{f}/config")
        more.append(f"_{f}")
    # WP / CMS specifics
    for p in ["wp-content/uploads", "wp-content/plugins", "wp-content/themes", "wp-includes",
              "wp-json", "wp-json/wp/v2", "xmlrpc.php", "wp-admin/install.php",
              "wp-admin/setup-config.php", "wp-admin/upgrade.php", "wp-admin/admin-ajax.php",
              "wp-admin/options-general.php", "wp-admin/users.php", "wp-admin/tools.php"]:
        more.append(p)
    words = dedup(base + more)
    # numeric filler to guarantee 5000
    i = 0
    while len(words) < 5000:
        cand = f"path/{i:04d}"
        if cand not in words:
            words.append(cand)
        i += 1
    return words[:5000]


def write(name, words):
    path = os.path.join(WL, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(words) + "\n")
    print(f"{name}: {len(words)} entries")


if __name__ == "__main__":
    write("common.txt", build_common())
    write("api.txt", build_api())
    write("files.txt", build_files())
    write("large.txt", build_large())
    print("done")
