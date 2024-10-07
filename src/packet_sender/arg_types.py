from argparse import ArgumentTypeError
from collections.abc import Callable
from json import JSONDecodeError
from os.path import isfile

from convert import command_to_packet, json_to_filter, json_to_packet
from scapy.arch.common import compile_filter
from scapy.error import Scapy_Exception
from scapy.interfaces import get_if_list
from scapy.packet import Packet
from scapy.utils import rdpcap


def interface(iface: str) -> str:
    if iface not in get_if_list():
        raise ArgumentTypeError(f"interface '{iface}' does not exist")
    return iface


def packet(pkt_json: str) -> Packet:
    try:
        return json_to_packet(pkt_json)
    except JSONDecodeError as e:
        raise ArgumentTypeError(f"invalid JSON string: {e}")
    except (TypeError, AssertionError) as e:
        raise ArgumentTypeError(str(e))


def positive_int(int_str: str) -> int:
    try:
        _int = int(int_str)
    except ValueError:
        _int = 0
    if _int < 1:
        raise ArgumentTypeError(f"invalid int value: '{int_str}'")
    return _int


def unsigned_float(float_str: str) -> float:
    try:
        _float = float(float_str)
    except ValueError:
        _float = -1
    if _float < 0:
        raise ArgumentTypeError(f"invalid float value: '{float_str}'")
    return _float


def bpf(bpf_str: str) -> str:
    try:
        compile_filter(bpf_str)
    except Scapy_Exception:
        raise ArgumentTypeError(f"invalid BPF filter: '{bpf_str}'")
    return bpf_str


def filter_func(filter_json: str) -> Callable[[Packet], bool]:
    try:
        return json_to_filter(filter_json)
    except JSONDecodeError as e:
        raise ArgumentTypeError(f"invalid JSON string: {e}")
    except (TypeError, AssertionError) as e:
        raise ArgumentTypeError(str(e))


def packet_command(command: str) -> Packet:
    try:
        return command_to_packet(command)
    except (AttributeError, NameError, SyntaxError, TypeError) as e:
        raise ArgumentTypeError(f"invalid scapy command: {type(e).__name__}: {e}")


def packet_path(path: str) -> Packet:
    if not isfile(path):
        raise ArgumentTypeError(f"invalid path: '{path}'")
    try:
        return rdpcap(path)[0]
    except Scapy_Exception:
        raise ArgumentTypeError(f"'{path}' is not a pcap file")
