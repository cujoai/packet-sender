## packet-sender
`packet-sender` is a command line interface for `scapy`, meant to enable the use of some of the `scapy` functionality without importing the library. This is achieved by encoding network packets as JSON strings e.g.
```commandline
'[{"__type__":"Ether","__data__":{"dst":"94:83:c4:27:f0:2e","src":"fc:5c:ee:22:61:7e","type":2048}},{"__type__":"IP","__data__":{"ihl":5,"id":23243,"flags":2,"proto":1,"src":"192.168.8.117","dst":"1.1.1.1"}},{"__type__":"ICMP","__data__":{"id":6,"seq":1,"unused":{"__type__":"bytes","__data__":""}}},{"__type__":"Raw","__data__":{"load":{"__type__":"bytes","__data__":"c9oDZwAAAAB2hw4AAAAAABAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc="}}}]'
```
### Calling packet-sender in Python
`packet-sender` can be called by Python code using the `subprocess` module. Use the `json-type-hints` package to serialize the input to JSON strings and deserialize the JSON output. To facilitate this use case, `packet-sender` can encode `scapy` packet creation commands and `pcap` files as Python dictionaries for easy editing e.g.
```commandline
packet-sender encode cmd "Ether(dst='ff:ff:ff:ff:ff:ff', src='6c:c7:ec:24:48:7f')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(sport=68, dport=67)/BOOTP(xid=RandInt(), flags=32768, chaddr=b'l\xc7\xec$H\x7f')/DHCP(options=[('message-type', 'discover'), ('server_id', '192.168.1.254'), ('hostname', 'Galaxy-S9'), ('vendor_class_id', 'android-dhcp-10'), ('param_req_list', [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]), 'end'])"
[
    {
        '__type__': 'Ether',
        '__data__': {'dst': 'ff:ff:ff:ff:ff:ff', 'src': '6c:c7:ec:24:48:7f'}
    },
    {
        '__type__': 'IP',
        '__data__': {'options': [], 'src': '0.0.0.0', 'dst': '255.255.255.255'}
    },
    {'__type__': 'UDP', '__data__': {'sport': 68, 'dport': 67}},
    {
        '__type__': 'BOOTP',
        '__data__': {
            'xid': {'__type__': 'RandInt'},
            'flags': 32768,
            'chaddr': b'l\xc7\xec\x7f'
        }
    },
    {
        '__type__': 'DHCP',
        '__data__': {
            'options': [
                ('message-type', 'discover'),
                ('server_id', '192.168.1.254'),
                ('hostname', 'Galaxy-S9'),
                ('vendor_class_id', 'android-dhcp-10'),
                ('param_req_list', [1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
                'end'
            ]
        }
    }
]
```
### Building packet-sender
use Docker to build packet-sender on Debian bookworm. The output will be compressed as tar.gz and named according to the machine hardware name (`uname -m`)
1. build Dockerfile.builder
    ```bash
    sudo docker build . -f Dockerfile.builder -t packet-sender-builder
    ```
2. run the builder with the packet-sender root directory mounted on /src
    ```bash
    sudo docker run -v "$(pwd):/src" packet-sender-builder
    ```