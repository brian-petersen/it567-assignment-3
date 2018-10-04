# Assignment 3 - Port Scanner

## Notes

1. Python 3.7.0 is the target version

2. macOS High Sierra is the development machine

3. Install needed dependencies

        pip install -r requirements.txt

4. `sudo` access is needed to send the raw packets with `scapy`

## Usage

The usage as documented by the tool itself is provided below

    $ ./scanner.py -h
    usage: scanner.py [-h] [-t TARGETS [TARGETS ...]] [-tF TARGETS_FILE]
                    [-p PORTS [PORTS ...]] [-v] [-sT] [-sU] [-T] [-o OUTPUT]
                    [-oF {html}]

    Scan for open ports (TCP and UDP) on a number of hosts. Can also perform a
    traceroute and ICMP ping to verify hosts.

    optional arguments:
    -h, --help            show this help message and exit
    -t TARGETS [TARGETS ...], --targets TARGETS [TARGETS ...]
                            Target hosts to scan as a single IP or CIDR
    -tF TARGETS_FILE, --targets-file TARGETS_FILE
                            File of targets (as a single IP or CIDR) on each line
    -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                            Ports to scan on target hosts as a single port or port
                            range
    -v, --verify          Verify hosts with an ICMP ping before performing port
                            scan
    -sT, --tcp            Scan TCP ports (using SYN scan)
    -sU, --udp            Scan UDP ports
    -T, --traceroute      Perform traceroute
    -o OUTPUT, --output OUTPUT
                            File to write report to
    -oF {html}, --output-format {html}
                            Format of output

### Main Features and Flags

* `-t` specifies targets. They can be a single IP address (e.g. 191.168.1.1) or a CIDR (e.g. 192.168.1.0/24). They are separated by spaces.
* `-tF` specifies a target file. Each target must be on its own line and in the format described above. Only one file is accepted.
* `-p` specifies ports to scan. They can be a single port (e.g. 80) or a range (e.g. 100-105). Additional ports can be provided with a space.
* `-v` specifies to verify the targets with a ping before scanning their ports.
* `-sT` specifies to perform a TCP SYN-ACK scan.
* `-sU` specifies to perform a UDP scan.
* `-o` specifies the output file to write to.
* `-oF` specifies the output file format. Accepted values are `html` only for now.

### Example

    $ sudo ./scanner.py -t 192.168.1.0/24 -sT -sU -p 80-100 -T -o test.html
    Results for host 192.168.1.1
    Traceroute: 192.168.1.1
    80/tcp OPEN
    53/tcp OPEN
    80/udp CLOSED
    53/udp OPEN|FILTERED

    ...