from cpp import cpp_parse
from protobuf import pb_parse
from py import py_parse
import time

# b_str = b'b6\xb2\x193*&Z$J\x04\x08\x06\x10\x03J\x04\x08\x02\x10\x03J\x04\x08\x05\x10\x01J\x04\x08\x01\x10\x01J\x04\x08\x03\x10\x03J\x04\x08\x04\x10\x01*\t\x1a\x07"\x05\x01\x02\x03\x04\x05'
# result = py_parse.parse(b_str, "7659")
# result = pb_parse.parse(b_str, "7659")
# result = cpp_parse.parse(b_str, "7659")
# print(result)

source = []
#
with open("20230702021809.txt", "r", encoding="utf-8") as source_file:
    lines = source_file.readlines()
    for line in lines:
        index = line[:10].find(" ")
        source.append((line[:index], eval(line[index+1:-1])))

total = len(source)

# with open("long_string3.bin", "wb") as f:
#     for each in source:
#         f.write(each[1])
# f = open("long_string.bin", "rb")
# each = ("675", f.read())
# total = 1
# length = 0
# for each in source:
#     length += len(each[1])
# print(length)
#

start_time = time.time()
for each in source:
    pb_parse.parse(each[1], each[0])
end_time = time.time()
print("google protocol buffer parse %d package(s) cost %f second(s)" % (total, end_time-start_time))

start_time = time.time()
for each in source:
    py_parse.parse(each[1], each[0])
end_time = time.time()
print("python parse %d package(s) cost %f second(s)" % (total, end_time-start_time))

start_time = time.time()
for each in source:
    cpp_parse.parse_tight(each[1], each[0])
end_time = time.time()
print("c++ parse %d package(s) cost %f second(s)" % (total, end_time-start_time))

