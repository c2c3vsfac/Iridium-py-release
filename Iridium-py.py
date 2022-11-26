import base64
import threading
import pcapy
import json
import parse_proto as pp
import time
import os
import re


def package_handle(hdr, data):
    sniff_datas.append(data)


def xor(b_data, b_key):
    decrypt_data = b""
    for j in range(len(b_data)):
        decrypt_data += (b_data[j] ^ b_key[j % len(b_key)]).to_bytes(1, byteorder="big", signed=False)
    return decrypt_data


def remove_magic(b_data):
    try:
        cut1 = b_data[6]
        cut2 = b_data[5]
        b_data = b_data[8 + 2:]
        b_data = b_data[:len(b_data) - 2]
        b_data = b_data[cut2:]
        return b_data[cut1:]
    except IndexError as e:
        print(e)


def get_packet_id(b_data):
    packet_id = int.from_bytes(b_data[2:4], byteorder="big", signed=False)
    return packet_id


def read_packet_id():
    f = open("packet_id.json", "r")
    d_packet_id = json.load(f)
    f.close()
    return d_packet_id


def get_proto_name_by_id(i_id):
    try:
        proto_name = d_pkt_id[str(i_id)]
        return proto_name
    except KeyError as e:
        print(e)
        return False


def sniff():
    while True:
        pcap.loop(1, package_handle)


def find_key():
    i = 0
    head = ""
    have_got_id_key = False
    have_got_data_key = False
    d_windseed = {}
    encrypted_windseed = b""
    while True:
        if i <= len(sniff_datas) - 1:
            b_data = sniff_datas[i]
            b_data = b_data[42:]
            i += 1
            if have_got_data_key and have_got_id_key:
                frg = b_data[9]
                sn = int.from_bytes(b_data[16:20], byteorder="little", signed=False)
                if frg + sn == first_frg + first_sn:
                    if frg not in d_windseed:
                        d_windseed[frg] = b_data[28:]
                    else:
                        continue
                    frgs = list(d_windseed.keys())
                    if frgs[0] + 1 == len(frgs):
                        sorted_frgs = sorted(d_windseed.items(), key=lambda x: x[0], reverse=True)
                        t_data = list(zip(*sorted_frgs))[1]
                        for frg_data in t_data:
                            encrypted_windseed += frg_data
                        offset = len(encrypted_windseed) - 56553
                        full_key = xor(encrypted_windseed[offset:], windseed_text)
                        keys = [full_key[i: i + 4096] for i in range(4096 - offset, len(full_key), 4096)]
                        decrypted_key = max(set(keys), key=keys.count)
                        pkg_parser = threading.Thread(target=parse, args=(decrypted_key,))
                        kcp_dealing = threading.Thread(target=handle_kcp, args=(id_key,))
                        pkg_parser.start()
                        kcp_dealing.start()
                        break
            else:
                if not head:
                    if len(b_data) > 20:
                        head = b_data[:2]
                    else:
                        continue
                if len(b_data) > 20:
                    if not have_got_id_key:
                        b_data = b_data[28:]
                        if b_data.startswith(b"$\x8f") or b_data.startswith(head):
                            continue
                        else:
                            id_key = xor(b_data[:4], b"Eg\x00\x70")
                            if id_key:
                                have_got_id_key = True
                    else:
                        packet_id = xor(b_data[28:32], id_key)
                        if packet_id == b"\x45\x67\x04\xaf":
                            first_frg = b_data[9]
                            first_sn = int.from_bytes(b_data[16:20], byteorder="little", signed=False)
                            have_got_data_key = True
                            d_windseed[first_frg] = b_data[28:]


def parse(decrypt_key):
    i = 0
    f_decrypt_data = open(now_time + ".txt", "w", encoding="utf-8")
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
            if packet_id in save_packet:
                proto_name = get_proto_name_by_id(packet_id)
                f = open(str(proto_name) + ".txt", "ab")
                f.write(b_data)
                f.close()
            proto_name = get_proto_name_by_id(packet_id)
            b_data = remove_magic(b_data)
            if proto_name:
                if packet_id == 5:
                    union_list = []
                    try:
                        data = pp.parse(b_data, str(packet_id))
                        for union_data in data["cmd_list"]:
                            each_data = pp.parse(base64.b64decode(union_data["body"]),
                                                 str(union_data["message_id"]))
                            if 'invokes' in each_data:
                                if 'argument_type' in each_data["invokes"][0]:
                                    argument_type = each_data["invokes"][0]['argument_type']
                                    if argument_type in union_cmd:
                                        if 'ability_data' in each_data["invokes"][0]:
                                            each_data["invokes"][0]['ability_data'] = pp.parse(
                                                base64.b64decode(each_data["invokes"][0]['ability_data']),
                                                union_cmd[argument_type])
                                    else:
                                        print("有未对应argument_type:" + str(argument_type))
                                    union_list.append({"AbilityInvocationsNotify": each_data})
                            elif 'invoke_list' in each_data:
                                if 'argument_type' in each_data["invoke_list"][0]:
                                    argument_type = each_data["invoke_list"][0]['argument_type']
                                    if argument_type in union_cmd:
                                        each_data["invoke_list"][0]['combat_data'] = pp.parse(
                                            base64.b64decode(each_data["invoke_list"][0]['combat_data']),
                                            union_cmd[argument_type])
                                    else:
                                        print("有未对应argument_type:" + str(argument_type))
                                    union_list.append({"CombatInvocationsNotify": each_data})
                        f_decrypt_data.write("UnionCmdNotify " + str(union_list) + "\n")
                    except Exception as e:
                        f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
                        print(e)
                elif packet_id == 1198:  # AbilityInvocationsNotify
                    try:
                        data = pp.parse(b_data, str(packet_id))
                        if 'invokes' in data:
                            if 'argument_type' in data["invokes"][0]:
                                argument_type = data["invokes"][0]['argument_type']
                                if argument_type in union_cmd:
                                    if 'ability_data' in data["invokes"][0]:
                                        data["invokes"][0]['ability_data'] = pp.parse(
                                            base64.b64decode(data["invokes"][0]['ability_data']),
                                            union_cmd[argument_type])
                                else:
                                    print("有未对应argument_type:" + str(argument_type))
                        f_decrypt_data.write("AbilityInvocationsNotify " + str(data) + "\n")
                    except Exception as e:
                        f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
                        print(e)
                elif packet_id == 319:  # CombatInvocationsNotify
                    try:
                        data = pp.parse(b_data, str(packet_id))
                        for invoke in data["invoke_list"]:
                            if 'argument_type' in invoke:
                                argument_type = invoke['argument_type']
                                if argument_type in union_cmd:
                                    invoke['combat_data'] = pp.parse(
                                        base64.b64decode(invoke['combat_data']), union_cmd[argument_type])
                                else:
                                    print("有未对应argument_type:" + str(argument_type))
                        f_decrypt_data.write("CombatInvocationsNotify " + str(data) + "\n")
                    except Exception as e:
                        f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
                        print(e)
                elif packet_id == 1135:  # ClientAbilityInitFinishNotify
                    try:
                        data = pp.parse(b_data, str(packet_id))
                        if 'invokes' in data:
                            for init_data in data["invokes"]:
                                if 'argument_type' in init_data:
                                    argument_type = init_data['argument_type']
                                    if argument_type in union_cmd:
                                        if 'ability_data' in init_data:
                                            init_data['ability_data'] = pp.parse(
                                                base64.b64decode(init_data['ability_data']),
                                                union_cmd[argument_type])
                                    else:
                                        print("有未对应argument_type:" + str(argument_type))
                        f_decrypt_data.write("ClientAbilityInitFinishNotify " + str(data) + "\n")
                    except Exception as e:
                        f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
                        print(e)
                elif packet_id == 1175:  # ClientAbilityChangeNotify
                    try:
                        data = pp.parse(b_data, str(packet_id))
                        if 'invokes' in data:
                            for init_data in data["invokes"]:
                                if 'argument_type' in init_data:
                                    argument_type = init_data['argument_type']
                                    if argument_type in union_cmd:
                                        if 'ability_data' in init_data:
                                            init_data['ability_data'] = pp.parse(
                                                base64.b64decode(init_data['ability_data']),
                                                union_cmd[argument_type])
                                    else:
                                        print("有未对应argument_type:" + str(argument_type))
                        f_decrypt_data.write("ClientAbilityChangeNotify " + str(data) + "\n")
                    except Exception as e:
                        f_decrypt_data.write(str(proto_name) + " " + str(b_data) + "\n")
                        print(e)
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
                    if head.startswith(b"\x45\x67") and frg == 0:
                        packt_id = get_packet_id(head)
                        una = int.from_bytes(data[20:24], byteorder="little", signed=False)
                        if (sn, una) not in handled_without_kcp_packet:
                            if packt_id not in skip_packet:
                                packet.append(data[28:28 + length])
                            handled_without_kcp_packet.append((sn, una))
                        skip = True
                    else:
                        skip = False
                        if head.startswith(b"\x45\x67"):
                            packt_id = get_packet_id(head)
                            if packt_id not in skip_packet:
                                if sn + frg not in handled_kcp_packet:
                                    if sn + frg not in kcp:
                                        kcp[sn + frg] = {frg: data[28: 28 + length]}
                                    else:
                                        kcp[sn + frg][frg] = data[28: 28 + length]
                                else:
                                    skip = True
                            else:
                                handled_kcp_packet.append(sn + frg)
                                skip = True
                            # {245:{36:data}}, 284:{:}}
                        else:
                            if sn + frg in kcp:
                                if frg in kcp[sn + frg]:
                                    skip = True
                                else:
                                    kcp[sn + frg][frg] = data[28: 28 + length]
                            else:
                                if sn + frg not in handled_kcp_packet:
                                    kcp[sn + frg] = {frg: data[28: 28 + length]}
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
                        handled_kcp_packet.append(key1)
                        del kcp[key1]
                        break


def read_windseed():
    f = open("plaintext.bin", "rb")
    b_windseed = f.read()
    f.close()
    return b_windseed


def read_config():
    f = open("config.json", "r")
    return json.load(f)


def read_union_cmd():
    f = open("ucn_id.json", "r")
    return json.load(f)


config = read_config()
windseed_text = read_windseed()
union_cmd = read_union_cmd()
d_pkt_id = read_packet_id()
sniff_datas = []
packet = []
handled_without_kcp_packet = []
handled_kcp_packet = []
kcp = {}
dev = config["device_name"]
if dev == "NPF_{}":
    with os.popen("getmac", "r") as c:
        text = c.read()
    iface = re.findall("(?<=_{).*?(?=})", text)[0]
    dev = "NPF_{%s}" % iface
    with open("config.json", "w", encoding="utf-8") as f:
        config["device_name"] = dev
        json.dump(config, f)
skip_packet = config["skip_packet_id"]
save_packet = config["save_packet_id"]
pkg_filter = "udp and port 22102 or port 22101"
lock = threading.Lock()
pcap = pcapy.open_live(dev, 1500, 0, 0)
pcap.setfilter(pkg_filter)
now_time = time.strftime("%Y%m%d%H%M%S")
sniffer = threading.Thread(target=sniff)
key_finder = threading.Thread(target=find_key)
sniffer.start()
key_finder.start()
