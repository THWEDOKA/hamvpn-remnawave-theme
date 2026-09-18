"""Exactly one AEZA route; preserve every existing client endpoint and neighbor."""
from copy import deepcopy

ENTRY = '193.233.222.244'
EXIT = '94.183.255.82'
R, B = 35443, 31443
TAG = 'ham-nl5-reverse-reality-backend'
ACCOUNT = 'ham-rs633-nl5'
UNIT = 'ham-rs633-nl5'


def backend(config, private, short):
    out = deepcopy(config)
    assert not any(i['tag'] == TAG or i.get('port') == B for i in out['inbounds'])
    out['inbounds'].append({'tag': TAG, 'listen': '127.0.0.1', 'port': B,
        'protocol': 'vless', 'settings': {'clients': [], 'decryption': 'none'},
        'sniffing': {'enabled': True, 'destOverride': ['http', 'tls']},
        'streamSettings': {'network': 'raw', 'security': 'reality', 'realitySettings': {
            'show': False, 'target': '127.0.0.1:8443', 'xver': 0,
            'serverNames': ['nl82.torcalc.ru'], 'privateKey': private, 'shortIds': [short],
            'minClientVer': '1.8.2'}}})
    return out


def wire(identity, public, short):
    return {'tag': 'exit-nl82', 'protocol': 'vless', 'settings': {'vnext': [{
        'address': '127.0.0.1', 'port': R, 'users': [{'id': identity,
        'encryption': 'none', 'flow': 'xtls-rprx-vision'}]}]}, 'streamSettings': {
        'network': 'raw', 'security': 'reality', 'realitySettings': {
            'serverName': 'nl82.torcalc.ru', 'fingerprint': 'firefox',
            'publicKey': public, 'shortId': short}}}


def entry(config, outbound):
    out = deepcopy(config)
    indices = [i for i, o in enumerate(out['outbounds']) if o.get('tag') == 'exit-nl82']
    assert len(indices) == 1 and outbound['tag'] == 'exit-nl82'
    out['outbounds'][indices[0]] = deepcopy(outbound)
    return out


def sshd():
    policy = {'AuthenticationMethods': 'publickey', 'PubkeyAuthentication': 'yes',
        'AuthorizedKeysFile': '/etc/ham-rs633-nl5/authorized_keys',
        'AuthorizedKeysCommand': 'none', 'TrustedUserCAKeys': 'none',
        'PasswordAuthentication': 'no', 'KbdInteractiveAuthentication': 'no',
        'AllowTcpForwarding': 'remote', 'AllowStreamLocalForwarding': 'no',
        'PermitListen': '127.0.0.1:' + str(R), 'PermitOpen': 'none', 'GatewayPorts': 'no',
        'AllowAgentForwarding': 'no', 'X11Forwarding': 'no', 'PermitTTY': 'no',
        'PermitUserRC': 'no', 'PermitTunnel': 'no', 'MaxSessions': '0',
        'ForceCommand': '/usr/sbin/nologin'}
    return policy, 'Match User ' + ACCOUNT + '\n' + ''.join('    ' + k + ' ' + v + '\n' for k, v in policy.items()) + 'Match all\n'


def client():
    return f'''Host aeza-nl5
    HostName {ENTRY}
    Port 22
    User {ACCOUNT}
    IdentityFile /var/lib/{ACCOUNT}/.ssh/id_ed25519
    UserKnownHostsFile /etc/{UNIT}/known_hosts
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    HostKeyAlgorithms ssh-ed25519
    IdentitiesOnly yes
    BatchMode yes
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PreferredAuthentications publickey
    ExitOnForwardFailure yes
    ServerAliveInterval 10
    ServerAliveCountMax 3
    ConnectTimeout 10
    RequestTTY no
    ForwardAgent no
    ForwardX11 no
    ControlMaster no
    ControlPath none
    LogLevel ERROR
    RemoteForward 127.0.0.1:{R} 127.0.0.1:{B}
'''


def unit():
    return f'''[Unit]
Description=HAM Netherlands-5 dedicated native reverse SSH Reality channel
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0
[Service]
Type=simple
User={ACCOUNT}
Group={ACCOUNT}
ExecStart=/usr/bin/ssh -NT -F /etc/{UNIT}/ssh_config aeza-nl5
Restart=always
RestartSec=3
TimeoutStopSec=10
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_INET AF_UNIX
IPAddressDeny=any
IPAddressAllow={ENTRY}/32
IPAddressAllow=127.0.0.1/32
[Install]
WantedBy=multi-user.target
'''
