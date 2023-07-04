from ctypes import cdll, c_int, c_char_p
import json
import os

current_path = os.path.dirname(os.path.abspath(__file__))
dll = cdll.LoadLibrary(current_path + "/Parser.dll")

dll.parser.restype = c_char_p

def parse(byte_str, packet_id:str):
    if byte_str:
        result:bytes = dll.parser(c_char_p(byte_str), c_int(len(byte_str)), c_char_p(packet_id.encode("ascii")))
        str_result = result.decode()
        dict_result = json.loads(str_result)
        json_result = json.dumps(dict_result, indent=2, ensure_ascii=False)
        dll.free_memory(c_char_p(result))
    else:
        json_result = "{}"
    return json_result


def parse_tight(byte_str, packet_id:str): # 直接使用c++返回的紧凑json
    result:bytes = dll.parser(c_char_p(byte_str), c_int(len(byte_str)), c_char_p(packet_id.encode("ascii")))
    index = result.rfind(b"}")

    str_result = result[:index+1].decode()
    return str_result

# b_str = b''
# result = parse(b_str, "675")
# print(result)