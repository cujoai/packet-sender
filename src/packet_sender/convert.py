import inspect
from collections.abc import Callable
from typing import cast

import json_hints
import scapy.layers.dhcp
import scapy.layers.dhcp6
import scapy.layers.dns
import scapy.layers.http
import scapy.layers.inet
import scapy.layers.inet6
import scapy.layers.l2
import scapy.layers.tls.all
from scapy.base_classes import Net
from scapy.config import conf
from scapy.fields import FlagValue
from scapy.packet import Packet
from scapy.volatile import RandInt, RandNum, RandShort

RANDOM_NUMBERS = [RandInt, RandShort, RandNum]
SCAPY_TYPES = {layer.__name__: layer for layer in conf.layers}
for rand_num in RANDOM_NUMBERS:
    SCAPY_TYPES[rand_num.__name__] = rand_num


def encode_layer(obj: object) -> object:
    object_class = type(obj)
    class_name = object_class.__name__
    if issubclass(object_class, Packet):
        layer = cast(Packet, obj)
        for field in ["chksum", "cksum", "len"]:
            if field in layer.fields:
                layer.delfieldval(field)
        return {"__type__": class_name, "__data__": layer.fields}
    if object_class in RANDOM_NUMBERS:
        init_args = inspect.signature(object_class).parameters.keys()
        if data := {key: getattr(obj, key) for key in init_args}:
            return {"__type__": class_name, "__data__": data}
        return {"__type__": class_name}
    return obj


def encode_simple_types(obj: object) -> object:
    if isinstance(obj, FlagValue):
        return obj.value
    if isinstance(obj, Net):
        return obj.net
    raise TypeError(f"{type(obj)} is not JSON serializable")


def packet_to_layer_list(pkt: Packet) -> list[Packet]:
    return [cast(Packet, pkt.getlayer(layer.__name__)) for layer in pkt.layers()]


def layer_list_to_packet(layer_list: list[Packet]) -> Packet:
    pkt = None
    for layer in layer_list:
        pkt = pkt / layer if pkt else layer
    return cast(Packet, pkt)


def json_to_packet(json_str: str) -> Packet:
    layer_list = json_hints.loads(json_str, hinted_types=SCAPY_TYPES)
    assert isinstance(layer_list, list) and len(layer_list) > 1, "packet is not a list of layers"
    for layer in layer_list:
        assert issubclass(type(layer), Packet), f"{type(layer).__name__} is not a layer"
    return layer_list_to_packet(layer_list)


def packet_to_json(pkt: Packet) -> str:
    return json_hints.dumps(
        packet_to_layer_list(pkt), encode_types=encode_layer, default=encode_simple_types
    )


def command_to_packet(cmd: str) -> Packet:
    return eval(cmd.encode(), SCAPY_TYPES)


def packet_to_dict(packet: Packet, minimize: bool = False):
    if minimize:
        packet.hide_defaults()
    return json_hints.loads(packet_to_json(packet), raise_on_unknown=False)


def json_to_filter(json_str: str) -> Callable[[Packet], bool]:
    _filter = json_hints.loads(json_str)
    assert isinstance(_filter, dict), "filter is not a dict"
    for _layer in _filter:
        assert isinstance(_filter[_layer], dict), f"filter[{_layer}] is not a dict"
        assert _layer in SCAPY_TYPES, f"'{_layer}' is not a valid layer"

    def filter_function(packet: Packet) -> bool:
        for layer in _filter:
            pkt_layer = packet.getlayer(layer)
            if not pkt_layer:
                return False
            for field in _filter[layer]:
                val = _filter[layer][field]
                field_val = pkt_layer.getfieldval(field)
                if isinstance(field_val, FlagValue):
                    field_val = field_val.value
                if isinstance(field_val, list):
                    if not set(val if isinstance(val, list) else [val]).issubset(field_val):
                        return False
                elif field_val != val:
                    return False
        return True

    return filter_function
