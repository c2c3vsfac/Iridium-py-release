from py import parser
import json

def parse(byte_str, packet_id:str):
    dict_result = parser.parse(byte_str, packet_id)
    json_result = json.dumps(dict_result, indent=2, ensure_ascii=False)
    return json_result

# b_str = b'b6\xb2\x193*&Z$J\x04\x08\x06\x10\x03J\x04\x08\x02\x10\x03J\x04\x08\x05\x10\x01J\x04\x08\x01\x10\x01J\x04\x08\x03\x10\x03J\x04\x08\x04\x10\x01*\t\x1a\x07"\x05\x01\x02\x03\x04\x05'
# result = parse(b_str, "7659")
# print(result)