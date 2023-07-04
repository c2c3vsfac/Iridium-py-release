import importlib
import json
from google.protobuf import json_format

def read_json(file):
    with open(file, "r", encoding="utf-8") as f:
        text = json.load(f)
    return text

d_pkt_id = read_json("packet_id.json")

def get_proto_name_by_id(i_id):
    try:
        proto_name = d_pkt_id[i_id]
        return proto_name
    except KeyError:
        return False

def parse(byte_str, packet_id:str):

    proto_name = get_proto_name_by_id(packet_id)
    # 动态导入指定的proto模块
    proto_module = importlib.import_module('protobuf.proto.%s_pb2' % proto_name)

    # 根据proto模块中定义的类创建实例
    dynamic_class = getattr(proto_module, proto_name)
    dynamic_obj = dynamic_class()

    # 将字节串解析为对象
    dynamic_obj.ParseFromString(byte_str)
    json_result = json_format.MessageToJson(dynamic_obj, preserving_proto_field_name=True, ensure_ascii=False)  # 不设为True会以小驼峰命名法命名字段名
    return json_result

# b_str = b'b6\xb2\x193*&Z$J\x04\x08\x06\x10\x03J\x04\x08\x02\x10\x03J\x04\x08\x05\x10\x01J\x04\x08\x01\x10\x01J\x04\x08\x03\x10\x03J\x04\x08\x04\x10\x01*\t\x1a\x07"\x05\x01\x02\x03\x04\x05'
# result = parse(b_str, "7659")
# print(result)