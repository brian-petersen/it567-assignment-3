#!/usr/bin/env python3

# Note sudo access is needed for scapy to run properly

# Points break down
# 40 for specifying a host and port and presenting output (for TCP)
# 10 for specifying multiple ports as PORT or PORT-PORT
# 10 for completing the base TCP with UDP scanning
# 10 for HTML output
# 5 for allowing ICMP pinging (with --verify) and reporting UDP status
# 5 for specifying hosts as a CIDR block
# 5 for traceroute
# 5 for reading hosts from a file
# Total points: 90

# Example usages:

# Print usage and help
# $ sudo ./scanner.py -h

# Perform TCP and UDP scanning for ports 53-80
# with traceroute and outputting to out.html
# $ sudo ./scanner.py -t 192.168.1.1 -T -sT -sU -p 53-80 -o out.html

import argparse
import re
from ipaddress import ip_network

from scapy.all import sr, sr1, send, IP, TCP, UDP, ICMP
from jinja2 import Template


MIN_PORT = 1
MAX_PORT = 65535

SINGLE_PORT = re.compile(r'^\d+$')
PORT_RANGE = re.compile(r'(^\d+)-(\d+)$')

OPEN = 1
CLOSED = 2
FILTERED = 3
OPEN_FILTERED = 4

OUTPUT_TEMPLATE = '''<html>
<head>
    <title>Scan Output</title>
    <style>
        html, body {
            font-family: Arial, Helvetica, sans-serif;
        }

        .result {
            padding: 10px;
            margin-bottom: 20px;
            border-radius: 5px;
            background: whitesmoke;
        }

        .result h2 {
            margin-top: 0;
        }

        table td {
            padding: 0 10px;
        }
    </style>
</head>
<body>
    <h1>Scan results</h1>
    {% for host in results %}
        <div class="result">
            <h2>{{ host }}</h2>
            {% if results[host].traceroute %}
                <h3>Traceroute</h3>
                <ol>
                {% for hop in results[host].traceroute %}
                    <li>{{ hop }}</li>
                {% endfor %}
                </ol>
            {% endif %}

            <h3>Ports</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Status</th>
                </tr>
                {% for port in results[host].tcp %}
                    <tr>
                        <td>{{ port }}</td>
                        <td>TCP</td>
                        <td>{{ results[host].tcp[port] }}</td>
                    </tr>
                {% endfor %}
                {% for port in results[host].udp %}
                    <tr>
                        <td>{{ port }}</td>
                        <td>UDP</td>
                        <td>{{ results[host].udp[port] }}</td>
                    </tr>
                {% endfor %}
            </table>
        </div>
    {% endfor %}
</body>
</html>

'''


def code_to_label(code):
    '''Converts a code to a readable label.'''
    if code == OPEN:
        return 'OPEN'
    elif code == CLOSED:
        return 'CLOSED'
    elif code == FILTERED:
        return 'FILTERED'
    elif code == OPEN_FILTERED:
        return 'OPEN|FILTERED'
    else:
        return 'UNKNOWN'


def icmp_scan(ips, timeout=0.5):
    '''Performs a ICMP request.
    returns: (live, unreachable) where live are hosts that replied
                                 and unreachable are all others
    '''
    ans, unans = sr(IP(dst=ips, ttl=20)/ICMP(), timeout=timeout, verbose=False)

    live = [req.dst for req, _ in ans]
    unreachable = [req.dst for req in unans]

    return live, unreachable


def tcp_syn_scan(ip, ports, timeout=0.2):
    '''Performs TCP SYN scan.'''
    results = {port: None for port in ports}

    # Send SYN packet
    ans, _ = sr(
        IP(dst=ip)/TCP(dport=ports, flags='S'),
        timeout=timeout,
        verbose=False,
    )

    # Iterate through responses
    # if SYN-ACK, count as open
    # if RST, count as closed
    reset_ports = []
    for req, res in ans:
        if not res.haslayer(TCP):
            continue

        tcp = res.getlayer(TCP)
        if tcp.flags == 0x12:
            results[tcp.sport] = OPEN
            reset_ports.append(tcp.sport)
        elif tcp.flags == 0x14:
            results[tcp.sport] = CLOSED

    # Reset open ports with ACK-RST packet
    send(IP(dst=ip)/TCP(dport=reset_ports, flags='R'), verbose=False)

    return results


def udp_scan(ip, ports, timeout=0.2):
    '''Performs UDP scan.'''
    results = {port: None for port in ports}

    ans, unans = sr(IP(dst=ip)/UDP(dport=ports),
                    timeout=timeout, verbose=False)
    for req, res in ans:
        if res.haslayer(UDP):
            results[req.dport] = OPEN
        elif res.haslayer(ICMP):
            icmp = res.getlayer(ICMP)
            if int(icmp.type) == 3 and icmp.code == 3:
                results[req.dport] = CLOSED
            elif int(icmp.type) == 3 and int(icmp.code) in [1, 2, 9, 10, 13]:
                results[req.dport] = FILTERED

    for req in unans:
        results[req.dport] = OPEN_FILTERED

    return results


def traceroute_scan(ip, max_hops=20, timeout=0.5):
    '''Performs ITCMP traceroute.'''
    hops = []
    for i in range(1, max_hops+1):
        res = sr1(IP(dst=ip, ttl=i) / ICMP(), verbose=False, timeout=timeout)
        if res is None:
            hops.append('*')
        elif res.src == ip:
            hops.append(res.src)
            break
        else:
            hops.append(res.src)
    return hops


def run_scans(targets, ports, tcp, udp, traceroute, verify_targets):
    if verify_targets:
        targets, _ = icmp_scan(targets)

    results = {}
    for target in targets:
        results[target] = {'tcp': {}, 'udp': {}, 'traceroute': None}
        if tcp:
            results[target]['tcp'] = tcp_syn_scan(target, ports)
        if udp:
            results[target]['udp'] = udp_scan(target, ports)
        if traceroute:
            results[target]['traceroute'] = traceroute_scan(target)
    return results


def print_results(results):
    for target, results in results.items():
        print(f'Results for host {target}')

        if results['traceroute']:
            print(f"Traceroute: {', '.join(results['traceroute'])}")

        for port, result in results['tcp'].items():
            if result:
                print(f'{port}/tcp {code_to_label(result)}')

        for port, result in results['udp'].items():
            if result:
                print(f'{port}/udp {code_to_label(result)}')

        print()


def make_output(output, format, results):
    for host, details in results.items():
        results[host]['tcp'] = {port: code_to_label(code) for port, code
                                in details['tcp'].items() if code is not None}
        results[host]['udp'] = {port: code_to_label(code) for port, code
                                in details['udp'].items() if code is not None}

    with open(output, 'w') as file:
        file.write(Template(OUTPUT_TEMPLATE).render(results=results))


def main():
    parser = argparse.ArgumentParser(
        description='''
Scan for open ports (TCP and UDP) on a number of hosts.
Can also perform a traceroute and ICMP ping to verify hosts.
'''
    )

    parser.add_argument(
        '-t',
        '--targets',
        nargs='+',
        help='Target hosts to scan as a single IP or CIDR',
        default=[],
    )

    parser.add_argument(
        '-tF',
        '--targets-file',
        help='File of targets (as a single IP or CIDR) on each line',
    )

    parser.add_argument(
        '-p',
        '--ports',
        nargs='+',
        help='Ports to scan on target hosts as a single port or port range',
        default=[],
    )

    parser.add_argument(
        '-v',
        '--verify',
        help='Verify hosts with an ICMP ping before performing port scan',
        action='store_true',
    )

    parser.add_argument(
        '-sT',
        '--tcp',
        help='Scan TCP ports (using SYN scan)',
        action='store_true',
    )

    parser.add_argument(
        '-sU',
        '--udp',
        help='Scan UDP ports',
        action='store_true',
    )

    parser.add_argument(
        '-T',
        '--traceroute',
        help='Perform traceroute',
        action='store_true',
    )

    parser.add_argument(
        '-o',
        '--output',
        help='File to write report to',
    )

    parser.add_argument(
        '-oF',
        '--output-format',
        help='Format of output',
        choices=['html'],
        default='html',
    )

    args = parser.parse_args()

    if not args.tcp and not args.udp and not args.traceroute:
        parser.error('no operation specified (-sT, -sU, -T)')

    raw_targets = args.targets[:]
    if args.targets_file:
        with open(args.targets_file) as f:
            raw_targets.extend([l.strip() for l in f.readlines()])

    targets = set()
    for target in raw_targets:
        try:
            network = ip_network(target)
        except ValueError:
            parser.error(f'invalid IP address or CIDR: {target}')

        if network.num_addresses == 1:
            targets.add(str(network.network_address))
        else:
            targets.update([str(ip) for ip in network.hosts()])
    targets = list(targets)

    ports = set()
    for port in args.ports:
        port_range_match = PORT_RANGE.match(port)
        if port_range_match:
            (begin, end) = port_range_match.group(1, 2)
            ports.update(range(int(begin), int(end)+1))
        elif SINGLE_PORT.match(port):
            ports.add(int(port))
        else:
            parser.error('invalid port format. Must be DIGIT or DIGIT-DIGIT')
    ports = [port for port in ports if MIN_PORT <= port <= MAX_PORT]

    if len(targets) == 0:
        parser.error('no targets specified')

    if (args.tcp or args.udp) and len(ports) == 0:
        parser.error('no ports specified with port scan')

    results = run_scans(
        targets,
        ports,
        args.tcp,
        args.udp,
        args.traceroute,
        args.verify
    )

    print_results(results)

    if args.output:
        make_output(args.output, args.output_format, results)


if __name__ == '__main__':
    main()
