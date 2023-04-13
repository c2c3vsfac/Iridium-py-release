import base64
import os
import re
import threading
import json
from scapy.all import sniff
import parse_proto as pp
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from MT19937_64 import MT19937_64
from csharp_rand import Rand
import time


def read_json(file):
    with open(file, "r", encoding="utf-8") as f:
        text = json.load(f)
    return text


def remove_magic(b_data):
    try:
        cut1 = b_data[6]
        cut2 = b_data[5]
        b_data = b_data[8 + 2:]
        b_data = b_data[:len(b_data) - 2]
        b_data = b_data[cut2:]
        return b_data[cut1:]
    except IndexError:
        pass


def package_handle(data):
    sniff_datas.append(bytes(data))


def xor(b_data, b_key):
    decrypt_data = b""
    for j in range(len(b_data)):
        decrypt_data += (b_data[j] ^ b_key[j % len(b_key)]).to_bytes(1, byteorder="big", signed=False)
    return decrypt_data


def get_init_key(b_data):
    key_id = int.from_bytes(b_data[28:30], byteorder="big", signed=False)
    possible_key_id = str(key_id ^ 0x4567)
    if possible_key_id in init_keys:
        key = base64.b64decode(init_keys[possible_key_id])
        return key
    else:
        return False


def guess_client_key(server_seed, send_time, pattern):
    guess = Rand()
    mt = MT19937_64()
    gen = MT19937_64()
    i_pattern = int.from_bytes(pattern, byteorder="big", signed=False)
    for i in range(1000):
        plus_time = send_time + i
        minus_time = send_time - i
        guess.seed(plus_time)
        client_seed = guess.uin64()
        mt_seed = client_seed ^ server_seed
        mt.seed(mt_seed)
        gen.seed(mt.int64())
        gen.int64()
        guess_num = i_pattern ^ gen.int64()
        if guess_num & 0xFFFF0000FF00FFFF == 0x4567000000000000:
            return mt_seed
        guess.seed(minus_time)
        client_seed = guess.uin64()
        mt_seed = client_seed ^ server_seed
        mt.seed(mt_seed)
        gen.seed(mt.int64())
        gen.int64()
        guess_num = i_pattern ^ gen.int64()
        if guess_num & 0xFFFF0000FF00FFFF == 0x4567000000000000:
            print("client_seed:%s" % client_seed)
            return mt_seed
    return False


def generate_key(seed):
    first = MT19937_64()
    first.seed(seed)
    gen = MT19937_64()
    gen.seed(first.int64())
    gen.int64()
    key = b""
    for i in range(0, 4096, 8):
        num = gen.int64()
        key += num.to_bytes(8, byteorder="big", signed=False)
    return key


def sniff_(iface_):
    sniff(iface=iface_, count=0, filter="udp port 22102||22101", prn=package_handle)


def find_key():
    i = 0
    init_key = b""
    client_send_time = 0
    i_server_seed = 0
    xor_key = b""
    while True:
        if i <= len(sniff_datas) - 1:
            b_data = sniff_datas[i]
            i += 1
            if not init_key:
                if len(b_data) > 70:
                    no_udp_data = b_data[42:]
                    if get_init_key(no_udp_data):
                        init_key = get_init_key(no_udp_data)
                    else:
                        continue
                else:
                    continue
            if not client_send_time:
                client_data = b_data[70:]
                data = xor(client_data, init_key)
                packet_id = get_packet_id(data)
                if packet_id == 190: # GetPlayerTokenReq
                    client_send_time = int(round(time.time() * 1000))
                    print("send_req_time:%d" % client_send_time)
                else:
                    continue
            if not i_server_seed:
                server_data = b_data[70:]
                data = xor(server_data, init_key)
                packet_id = get_packet_id(data)
                if packet_id == 196: # GetPlayerTokenRsp
                    data = remove_magic(data)
                    plain = pp.parse(data, str(packet_id))
                    server_encrypted_seed = base64.b64decode(plain['server_rand_key'])
                    server_seed = rsa_decrypt(server_encrypted_seed)
                    i_server_seed = int.from_bytes(server_seed, byteorder='big', signed=False)
                    print("server_seed:%d" % i_server_seed)
                else:
                    continue
            if not xor_key:
                if len(b_data) > 70:
                    no_kcp_data = b_data[70:]
                    test_data = xor(no_kcp_data[:2], init_key)
                    if test_data != b"Eg":
                        head = no_kcp_data[:8]
                        xor_seed = guess_client_key(i_server_seed, client_send_time, head)
                        if xor_seed:
                            xor_key = generate_key(xor_seed)
                            print("xor_key:%s" % str(xor_key))
                        else:
                            print("please retry")
                            exit(-1)
                else:
                    continue
            if xor_key:
                pkg_parser = threading.Thread(target=parse, args=(xor_key,))
                kcp_dealing = threading.Thread(target=handle_kcp, args=(xor_key[:4],))
                pkg_parser.start()
                kcp_dealing.start()
                break


def get_packet_id(b_data):
    packet_id = int.from_bytes(b_data[2:4], byteorder="big", signed=False)
    return packet_id


def rsa_decrypt(data: bytes) -> bytes:
    with open("./keys/private_key_4.pem", 'r') as rsa_file:
        server_private_key = RSA.import_key(rsa_file.read())
    dec = PKCS1_v1_5.new(server_private_key)
    chunk_size = 256
    out = b''
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        out += dec.decrypt(chunk, None)
    return out


def parse(decrypt_key):
    i = 0
    f_decrypt_data = open("./sniffer_output/" + now_time + ".txt", "w", encoding="utf-8")
    while True:
        if i <= len(packet) - 1:
            get = False
            try:
                if i >= 50:
                    get = lock.acquire()
                    for j in range(50):
                        packet.pop(0)
                    i -= 50
            finally:
                if get:
                    lock.release()
            b_data = packet[i]
            i += 1
            b_data = xor(b_data, decrypt_key)
            packet_id = get_packet_id(b_data)
            proto_name = get_proto_name_by_id(packet_id)
            b_data = remove_magic(b_data)
            # f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
            if packet_id == 75:  # UnionCmdNotify
                union_list = []
                try:
                    data = pp.parse(b_data, str(packet_id))
                    for union_data in data["cmd_list"]:
                        each_data = pp.parse(base64.b64decode(union_data["body"]),
                                             str(union_data["message_id"]))
                        if 'invokes' in each_data:
            #                 if 'argumentType' in each_data["invokes"][0]:
            #                     argument_type = each_data["invokes"][0]['argumentType']
            #                     if argument_type in union_cmd:
            #                         if 'abilityData' in each_data["invokes"][0]:
            #                             each_data["invokes"][0]['abilityData'] = pp.parse(
            #                                 base64.b64decode(each_data["invokes"][0]['abilityData']),
            #                                 union_cmd[argument_type])
            #                     else:
            #                         print("有未对应argument_type:" + str(argument_type))
                            union_list.append({"AbilityInvocationsNotify": each_data})
                        elif 'invokeList' in each_data:
            #                 if 'argumentType' in each_data["invokeList"][0]:
            #                     argument_type = each_data["invokeList"][0]['argumentType']
            #                     if argument_type in union_cmd:
            #                         each_data["invokeList"][0]["combatData"] = pp.parse(
            #                             base64.b64decode(each_data["invokeList"][0]["combatData"]),
            #                             union_cmd[argument_type])
            #                     else:
            #                         print("有未对应argument_type:" + str(argument_type))
                            union_list.append({"CombatInvocationsNotify": each_data})
                    f_decrypt_data.write("UnionCmdNotify " + str(union_list) + "\n")
                except Exception as e:
                    f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
                    print(e)
            # elif packet_id == 1155:  # AbilityInvocationsNotify
            #     try:
            #         data = pp.parse(b_data, str(packet_id))
            #         if 'invokes' in data:
            #             if 'argumentType' in data["invokes"][0]:
            #                 argument_type = data["invokes"][0]['argumentType']
            #                 if argument_type in union_cmd:
            #                     if "abilityData" in data["invokes"][0]:
            #                         data["invokes"][0]["abilityData"] = pp.parse(
            #                             base64.b64decode(data["invokes"][0]["abilityData"]),
            #                             union_cmd[argument_type])
            #                 elif argument_type == "ABILITY_INVOKE_ARGUMENT_META_REMOVE_ABILITY":
            #                     if "abilityData" in data["invokes"][0]:
            #                         print("发现不为空的ability_data: %s" % data["invokes"][0]["abilityData"])
            #                 else:
            #                     print("有未对应argument_type:" + str(argument_type))
            #         f_decrypt_data.write("AbilityInvocationsNotify " + str(data) + "\n")
            #     except Exception as e:
            #         f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
            #         print(e)
            # elif packet_id == 323:  # CombatInvocationsNotify
            #     try:
            #         data = pp.parse(b_data, str(packet_id))
            #         for invoke in data["invokeList"]:
            #             if 'argumentType' in invoke:
            #                 argument_type = invoke['argumentType']
            #                 if argument_type in union_cmd:
            #                     invoke["combatData"] = pp.parse(
            #                         base64.b64decode(invoke["combatData"]), union_cmd[argument_type])
            #                 else:
            #                     print("有未对应argument_type:" + str(argument_type))
            #         f_decrypt_data.write("CombatInvocationsNotify " + str(data) + "\n")
            #     except Exception as e:
            #         f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
            #         print(e)
            # elif packet_id == 1198:  # ClientAbilityInitFinishNotify
            #     try:
            #         data = pp.parse(b_data, str(packet_id))
            #         if 'invokes' in data:
            #             for init_data in data["invokes"]:
            #                 if 'argumentType' in init_data:
            #                     argument_type = init_data['argumentType']
            #                     if argument_type in union_cmd:
            #                         if "abilityData" in init_data:
            #                             init_data["abilityData"] = pp.parse(
            #                                 base64.b64decode(init_data["abilityData"]),
            #                                 union_cmd[argument_type])
            #                     else:
            #                         print("有未对应argument_type:" + str(argument_type))
            #         f_decrypt_data.write("ClientAbilityInitFinishNotify " + str(data) + "\n")
            #     except Exception as e:
            #         f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
            #         print(e)
            # elif packet_id == 1129:  # ClientAbilityChangeNotify
            #     try:
            #         data = pp.parse(b_data, str(packet_id))
            #         if 'invokes' in data:
            #             for init_data in data["invokes"]:
            #                 if 'argumentType' in init_data:
            #                     argument_type = init_data['argumentType']
            #                     if argument_type in union_cmd:
            #                         if "abilityData" in init_data:
            #                             init_data["abilityData"] = pp.parse(
            #                                 base64.b64decode(init_data["abilityData"]),
            #                                 union_cmd[argument_type])
            #                     else:
            #                         print("有未对应argument_type:" + str(argument_type))
            #         f_decrypt_data.write("ClientAbilityChangeNotify " + str(data) + "\n")
            #     except Exception as e:
            #         f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
            #         print(e)
            else:
                try:
                    data = pp.parse(b_data, str(packet_id))
                    f_decrypt_data.write(str(proto_name) + " " + str(data) + "\n")
                except Exception as e:
                    print(str(proto_name) + " Error")
                    print(e)
                    f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")


def handle_kcp(id_key):
    i = 6
    while True:
        if i <= len(sniff_datas) - 1:
            get = False
            try:
                if i >= 100:
                    get = lock.acquire()
                    for j in range(100):
                        sniff_datas.pop(0)
                    i -= 100
            finally:
                if get:
                    lock.release()
            data = sniff_datas[i]
            i += 1
            data = data[42:]
            skip = False
            while len(data) != 0:
                length = int.from_bytes(data[24:28], byteorder="little", signed=False)
                if length == 0:
                    data = data[28:]
                    continue
                else:
                    head = xor(data[28:32], id_key)
                    frg = data[9]
                    sn = int.from_bytes(data[16:20], byteorder="little", signed=False)
                    if frg + sn in skip_packet:
                        skip = True
                    else:
                        if head.startswith(b"\x45\x67") and frg == 0:
                            packet.append(data[28:28 + length])
                            skip_packet.append(sn)
                            skip = True
                        else:
                            skip = False
                            if head.startswith(b"\x45\x67"):
                                kcp[sn + frg] = {frg: data[28: 28 + length]}
                                # {245:{36:data}}, 284:{:}}
                            else:
                                try:
                                    if frg in kcp[sn + frg]:
                                        skip = True
                                    else:
                                        kcp[sn + frg][frg] = data[28: 28 + length]
                                except KeyError:
                                    skip = True
                    offset = length + 28
                    data = data[offset:]
            if not skip:
                for key1, value1 in kcp.items():
                    frgs = list(value1.keys())
                    if len(frgs) == frgs[0] + 1:
                        sorted_dict = sorted(value1.items(), key=lambda x: x[0], reverse=True)
                        t_data = list(zip(*sorted_dict))[1]
                        b_data = b""
                        for frg_data in t_data:
                            b_data += frg_data
                        packet.append(b_data)
                        skip_packet.append(key1)
                        del kcp[key1]
                        break


def get_proto_name_by_id(i_id):
    try:
        proto_name = d_pkt_id[str(i_id)]
        return proto_name
    except KeyError:
        return False


config = read_json("config.json")
init_keys = read_json("Keys.json")
d_pkt_id = read_json("packet_id.json")
# union_cmd = read_json("ucn_id.json")
dev = config["device_name"]
if dev == "\\Device\\NPF_{}":
    with os.popen("getmac", "r") as c:
        text = c.read()
    iface = re.findall("(?<=_{).*?(?=})", text)[0]
    dev = "\\Device\\NPF_{%s}" % iface
    with open("config.json", "w", encoding="utf-8") as f:
        config["device_name"] = dev
        json.dump(config, f)
pkg_filter = "udp and port 22102 or port 22101"
sniff_datas = []
packet = []
skip_packet = []
kcp = {}
lock = threading.Lock()
now_time = time.strftime("%Y%m%d%H%M%S")
sniffer = threading.Thread(target=sniff_, args=(dev,))
key_finder = threading.Thread(target=find_key)
sniffer.start()
key_finder.start()

