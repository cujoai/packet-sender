import argparse
import sys
import time
from collections.abc import Callable
from contextlib import contextmanager

import arg_types
import convert
from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff, srp1


@contextmanager
def permission_error():
    try:
        yield
    except PermissionError:
        print("error: Operation not permitted")
        sys.exit(1)


def _send(pkt: Packet, count: int, inter: float, iface: str | None):
    start_time = time.time()
    with permission_error():
        sendp(x=pkt, count=count, inter=inter, iface=iface, verbose=False)
    duration = round(time.time() - start_time, 3)
    print(f"sent {count} packet{'s' if count > 1 else ''} in {duration}s")


def _sr(
    bpf: str | None,
    filter_func: Callable[[Packet], bool] | None,
    timeout: int,
    iface: str | None,
    json: bool,
    pkt: Packet | None = None,
):
    with permission_error():
        if pkt and not (bpf or filter_func):
            res = srp1(pkt, timeout=timeout, iface=iface, verbose=False)
        else:
            s = sniff(
                iface=iface,
                filter=bpf,
                started_callback=lambda: sendp(x=pkt, iface=iface, verbose=False) if pkt else None,
                lfilter=filter_func,
                count=1,
                timeout=timeout,
            )
            res = s.res[0] if s.res else None
    if res:
        if json:
            print(convert.packet_to_json(res))
        else:
            print(res.command())


def _encode(pkt: Packet, minimize: bool):
    from rich.console import Console
    from rich.pretty import pprint

    pkt_dict = convert.packet_to_dict(packet=pkt, minimize=minimize)
    pprint(pkt_dict, console=Console(width=92), indent_guides=False)


if __name__ == "__main__":
    # shared argument parsers
    iface_parser = argparse.ArgumentParser(add_help=False)
    iface_parser.add_argument(
        "-i", "--iface", type=arg_types.interface, help="use the specified network interface"
    )
    minimize_parser = argparse.ArgumentParser(add_help=False)
    minimize_parser.add_argument(
        "-m",
        "--minimize",
        action="store_true",
        help="minimize the packet by removing any default field values",
    )
    packet_parser = argparse.ArgumentParser(add_help=False)
    packet_parser.add_argument(
        "pkt", metavar="PACKET", type=arg_types.packet, help="a packet encoded as a JSON string"
    )

    main_parser = argparse.ArgumentParser(
        prog="packet-sender", description="send, sniff, or encode packets"
    )
    main_parser.add_argument("--version", action="store_true", help="print the program version")
    subparsers = main_parser.add_subparsers(title="action")

    send_parser = subparsers.add_parser(
        "send",
        parents=[iface_parser, packet_parser],
        help="send packet(s)",
        description="send a packet, or any number of packet instances",
    )
    send_parser.add_argument(
        "-c",
        "--count",
        type=arg_types.positive_int,
        default=1,
        help="number of packets to send (default: 1)",
    )
    send_parser.add_argument(
        "--inter",
        type=arg_types.unsigned_float,
        default=0,
        help="time (in s) between sending two packets (default: 0)",
    )
    send_parser.set_defaults(action=_send)

    sniff_parser = subparsers.add_parser(
        "sniff",
        parents=[iface_parser],
        help="capture a packet",
        description="capture packets and return the first one to match the filters",
    )
    sniff_parser.add_argument(
        "--bpf", type=arg_types.bpf, help="BPF filter to apply when sniffing packets"
    )
    sniff_parser.add_argument(
        "-f",
        "--filter",
        metavar="FILTER",
        dest="filter_func",
        type=arg_types.filter_func,
        help=(
            "a JSON encoded, nested Python dictionary representing packet layers, fields and"
            " their values to be used as a filter when sniffing packets"
            ' e.g. {"UDP": {"dport": 67}}'
        ),
    )
    sniff_parser.add_argument(
        "-j", "--json", action="store_true", help="encode the output packet as a JSON string"
    )
    sniff_parser.add_argument(
        "-t",
        "--timeout",
        type=arg_types.positive_int,
        default=5,
        help="stop sniffing after a given number of seconds (default: 5)",
    )
    sniff_parser.set_defaults(action=_sr)

    sr_parser = subparsers.add_parser(
        "sr",
        add_help=False,
        parents=[packet_parser, sniff_parser],
        help="send a packet and capture the response",
        description=(
            "send a packet and capture the response. First packet to match the filters is"
            " considered the response. If no filter is given, will try to determined the"
            " response packet automatically"
        ),
    )
    sr_parser.set_defaults(action=_sr)

    encode_parser = subparsers.add_parser(
        "encode",
        help="encode a packet as a Python dict",
        description="encode a packet as a Python dict",
    )
    encode_subparsers = encode_parser.add_subparsers(title="type", required=True)

    encode_cmd_parser = encode_subparsers.add_parser(
        "cmd",
        parents=[minimize_parser],
        help="encode a scapy command",
        description="encode scapy command used to create the packet",
    )
    encode_cmd_parser.add_argument(
        "pkt",
        metavar="COMMAND",
        type=arg_types.packet_command,
        help="scapy command used to create the packet",
    )
    encode_cmd_parser.set_defaults(action=_encode)

    encode_pcap_parser = encode_subparsers.add_parser(
        "pcap",
        parents=[minimize_parser],
        help="encode a pcap file",
        description="encode the first packet in a pcap file",
    )
    encode_pcap_parser.add_argument(
        "pkt", metavar="PATH", type=arg_types.packet_path, help="pcap file path"
    )
    encode_pcap_parser.set_defaults(action=_encode)

    args = vars(main_parser.parse_args())
    action = args.pop("action", None)
    if action:
        args.pop("version")
        action(**args)
    elif args["version"]:
        print("version: 1.0")
    else:
        main_parser.print_help()
    sys.exit()
