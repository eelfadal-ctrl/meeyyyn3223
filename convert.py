import urllib.parse
import re

with open('dfgigfjh.txt', 'r', encoding='utf-8') as f:
    lines = [line.strip() for line in f if line.strip()]

proxies = []
for line in lines:
    if line.startswith('vless://'):
        match = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?(.+?)#(.+)', line)
        if not match:
            continue
        uuid, server, port, params, name = match.groups()
        params_dict = dict(urllib.parse.parse_qsl(params))
        path = urllib.parse.unquote(params_dict.get('path', '/'))
        host = params_dict.get('host', server)
        sni = params_dict.get('sni', host)
        proxies.append(f'''  - name: "{name}"
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    network: ws
    tls: true
    skip-cert-verify: true
    servername: {sni}
    ws-opts:
      path: "{path}"
      headers:
        Host: {host}
''')
    elif line.startswith('trojan://'):
        match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)\?(.+?)#(.+)', line)
        if not match:
            continue
        password, server, port, params, name = match.groups()
        params_dict = dict(urllib.parse.parse_qsl(params))
        path = urllib.parse.unquote(params_dict.get('path', '/'))
        host = params_dict.get('host', server)
        sni = params_dict.get('sni', host)
        proxies.append(f'''  - name: "{name}"
    type: trojan
    server: {server}
    port: {port}
    password: {password}
    network: ws
    tls: true
    skip-cert-verify: true
    sni: {sni}
    ws-opts:
      path: "{path}"
      headers:
        Host: {host}
''')

proxy_names = [re.search(r'name: "([^"]+)"', p).group(1) for p in proxies]

output = "proxies:\n" + "".join(proxies)
output += "\nproxy-groups:\n  - name: \"Proxy\"\n    type: select\n    proxies:\n"
for n in proxy_names:
    output += f'      - "{n}"\n'
output += "\nrules:\n  - MATCH,Proxy\n"

with open('clash.yaml', 'w', encoding='utf-8') as f:
    f.write(output)

print(f"Generated {len(proxies)} proxies")
