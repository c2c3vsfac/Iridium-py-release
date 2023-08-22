import struct
import json
import base64
import re


def varint(now_location, byte_str):
    offset = 0
    data = byte_str[now_location] & 0b1111111
    while True:
        if byte_str[now_location] >> 7:
            offset += 1
            now_location += 1
            data = ((byte_str[now_location] & 0b1111111) << (7 * offset)) | data
        else:
            break
    return data, offset


def judge_type(prop_name):
    zero = ["int32", "int64", "uint32", "uint64", "sint32", "sint64", "bool", "enum"]
    one = ["fixed64", "sfixed64", "double"]
    five = ["fixed32", "sfixed32", "float"]
    if prop_name in zero:
        return 0
    elif prop_name in one:
        return 1
    elif prop_name in five:
        return 5
    else:
        return 2


def parse(byte_str, packet_id: str, *args):
    if len(args) == 0:
        encoding_rules, prop_names = all_serial[packet_id]
    elif len(args) == 1:
        encoding_rules, prop_names = args[0]
    elif len(args) == 2:
        encoding_rules, prop_names = args
    else:
        encoding_rules, prop_names = args[0], args[1]
    decode_data = {}
    i = 0
    while i < len(byte_str):
        if len(args) == 3:
            data_type = judge_type(encoding_rules["1"])
            data_id = "1"
        else:
            data_type = byte_str[i] & 0b111
            data_id, offset = varint(i, byte_str)
            data_id >>= 3
            i += offset
            i += 1
            data_id = str(data_id)
        if data_id in encoding_rules:
            if data_type == 0:
                data, offset = varint(i, byte_str)
                if encoding_rules[data_id] == "bool":
                    data = bool(data)
                    decode_data[prop_names[data_id]] = data
                elif encoding_rules[data_id] == "enum":
                    enum_name = list(prop_names[data_id].keys())
                    enum_prop = list(prop_names[data_id].values())
                    decode_data[enum_name[0]] = enum_prop[0][str(data)]
                elif isinstance(encoding_rules[data_id], list):
                    if encoding_rules[data_id][0] == "enum":
                        enum_encode = encoding_rules[data_id][1]
                        decode_data[prop_names[data_id]] = enum_encode[str(data)]
                elif encoding_rules[data_id] in ["int32", "int64"]:
                    if data >> 63:
                        data = -((data ^ 0xFFFFFFFFFFFFFFFF) + 1)  # uint转int
                    decode_data[prop_names[data_id]] = data
                elif encoding_rules[data_id] in ["sint32", "sint64"]:
                    data = (data >> 1) ^ -(data & 1)
                    decode_data[prop_names[data_id]] = data
                else:
                    decode_data[prop_names[data_id]] = data
                i += offset
                i += 1
            elif data_type == 1:
                if encoding_rules[data_id] == "double":
                    decode_data[prop_names[data_id]] = struct.unpack("<d", byte_str[i:i + 8])[0]
                elif encoding_rules[data_id] == "sfixed64":
                    decode_data[prop_names[data_id]] = int.from_bytes(byte_str[i:i + 8], byteorder="little",
                                                                      signed=True)
                elif encoding_rules[data_id] == "fixed64":
                    decode_data[prop_names[data_id]] = int.from_bytes(byte_str[i:i + 8], byteorder="little",
                                                                      signed=False)
                i += 8
            elif data_type == 5:
                if encoding_rules[data_id] == "float":
                    decode_data[prop_names[data_id]] = struct.unpack("<f", byte_str[i:i + 4])[0]
                elif encoding_rules[data_id] == "sfixed32":
                    decode_data[prop_names[data_id]] = int.from_bytes(byte_str[i:i + 4], byteorder="little",
                                                                      signed=True)
                elif encoding_rules[data_id] == "fixed32":
                    decode_data[prop_names[data_id]] = int.from_bytes(byte_str[i:i + 4], byteorder="little",
                                                                      signed=False)
                i += 4
            elif data_type == 2:
                length, offset = varint(i, byte_str)
                i += offset
                i += 1
                if encoding_rules[data_id] == "string":
                    decode_data[prop_names[data_id]] = byte_str[i: i + length].decode()
                elif encoding_rules[data_id] == "bytes":
                    decode_data[prop_names[data_id]] = base64.b64encode(byte_str[i: i + length]).decode("ascii")
                elif isinstance(encoding_rules[data_id], dict):
                    if "map" in encoding_rules[data_id]:
                        type_dict = {"1": encoding_rules[data_id]["map"][0], "2": encoding_rules[data_id]["map"][1]}
                        prop_name = prop_names[data_id]
                        map_private_prop_name = {"1": "first", "2": "second"}
                        if prop_name not in decode_data:
                            decode_data[prop_name] = {}
                        map_data = parse(byte_str[i: i + length], packet_id, type_dict, map_private_prop_name)
                        if "first" not in map_data:
                            map_data["first"] = 0
                        if "second" not in map_data:
                            map_data["second"] = 0
                        try:
                            decode_data[prop_name].update({map_data["first"]: map_data["second"]})
                        except KeyError as e:
                            print(e)
                            print(packet_id)
                            print(map_data)
                    elif "repeated" in encoding_rules[data_id]:
                        if prop_names[data_id] not in decode_data:
                            decode_data[prop_names[data_id]] = []
                        repeated_rule, repeated_name = encoding_rules[data_id]["repeated"]
                        repeated_data = parse(byte_str[i: i + length], packet_id, repeated_rule, repeated_name)
                        decode_data[prop_names[data_id]].append(repeated_data)
                elif isinstance(encoding_rules[data_id], list):
                    invoke_data = parse(byte_str[i: i + length], packet_id, encoding_rules[data_id][0],
                                        encoding_rules[data_id][1])
                    decode_data[prop_names[data_id]] = invoke_data
                elif encoding_rules[data_id].startswith("repeated_"):
                    data_type = re.sub("repeated_", "", encoding_rules[data_id])
                    j = i
                    if data_type == "enum":
                        repeated_prop_name: str = prop_names[data_id][0]
                        repeated_encoding_rules = {"1": "uint32"}
                    else:
                        repeated_prop_name: str = prop_names[data_id]
                        repeated_encoding_rules = {"1": data_type}
                    repeated_prop_names = {"1": "1"}
                    if repeated_prop_name not in decode_data:
                        decode_data[repeated_prop_name] = []
                    if data_type == "string":
                        decode_data[repeated_prop_name].append(byte_str[j: i + length].decode())
                    else:
                        while j < i + length:
                            repeated_data = parse(byte_str[j: i + length], packet_id,
                                                  repeated_encoding_rules, repeated_prop_names, data_type)
                            if len(repeated_data) == 2:
                                repeated_offset, repeated_data = repeated_data
                                j += repeated_offset
                                if data_type == "enum":
                                    enum_encoding_rules = prop_names[data_id][1]
                                    decode_data[repeated_prop_name].append(enum_encoding_rules[str(repeated_data["1"])])
                                else:
                                    decode_data[repeated_prop_name].append(repeated_data["1"])
                i += length
            if len(args) == 3:
                return i, decode_data
    return decode_data


def read_json_packet(json_name):
    f = open(json_name, "r")
    serial = json.load(f)
    return serial


all_serial = read_json_packet("packet_serialization.json")
ucn = read_json_packet("ucn_serialization.json")
all_serial.update(ucn)
