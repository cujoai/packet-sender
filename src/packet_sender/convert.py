from collections.abc import Callable
from typing import cast

import json_hints
import scapy.layers.all
from scapy.fields import FlagValue
from scapy.packet import Packet
from scapy.volatile import RandNum

layers = {k: v for k, v in scapy.layers.all.__dict__.items() if isinstance(v, type)}


def encode_layer(obj: object) -> object:
    object_class = type(obj)
    class_name = object_class.__name__
    if issubclass(object_class, Packet):
        layer = cast(Packet, obj)
        for field in ["chksum", "cksum", "len"]:
            if field in layer.fields:
                layer.delfieldval(field)
        return {"__type__": class_name, "__data__": layer.fields}
    if isinstance(obj, FlagValue):
        return obj.value
    if issubclass(object_class, RandNum):
        return {"__type__": class_name}
    return obj


def packet_to_layer_list(pkt: Packet) -> list[Packet]:
    return [cast(Packet, pkt.getlayer(layer.__name__)) for layer in pkt.layers()]


def layer_list_to_packet(layer_list: list[Packet]) -> Packet:
    pkt = None
    for layer in layer_list:
        pkt = pkt / layer if pkt else layer
    return cast(Packet, pkt)


def json_to_packet(json_str: str) -> Packet:
    layer_list = json_hints.loads(json_str, hinted_types=layers)
    assert isinstance(layer_list, list) and len(layer_list) > 1, "packet is not a list of layers"
    for layer in layer_list:
        assert issubclass(type(layer), Packet), f"{type(layer).__name__} is not a layer"
    return layer_list_to_packet(layer_list)


def packet_to_json(pkt: Packet) -> str:
    return json_hints.dumps(packet_to_layer_list(pkt), encode_types=encode_layer)


def command_to_packet(cmd: str) -> Packet:
    return eval(cmd.encode(), layers)


def packet_to_dict(packet: Packet, minimize: bool = False):
    if minimize:
        packet.hide_defaults()
    return json_hints.loads(packet_to_json(packet), raise_on_unknown=False)


def json_to_filter(json_str: str) -> Callable[[Packet], bool]:
    _filter = json_hints.loads(json_str)
    assert isinstance(_filter, dict), "filter is not a dict"
    for _layer in _filter:
        assert isinstance(_filter[_layer], dict), f"filter[{_layer}] is not a dict"
        assert _layer in layers, f"'{_layer}' is not a valid layer"

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
