# Iridium-py-release
the package sniffer for genshin impact/yuanshen

**Special thanks to [Akka0](https://github.com/Akka0),
[Sorapointa](https://github.com/Sorapointa),[tamilpp25](https://github.com/tamilpp25), [unipendix](https://github.com/BUnipendix).**

原理详见[MagicSniffer](https://github.com/Sorapointa/MagicSniffer)。

The principle can be found at [MagicSniffer](https://github.com/Sorapointa/MagicSniffer).

## Usage

安装scapy，参见[nahida](https://github.com/Asassong/nahida)

## 后续版本使用

获得对应版本的proto文件(比如[NickTheHuy](https://github.com/NickTheHuy))，运行[iridium-utils](https://github.com/c2c3vsfac/Iridium-utils)中的get_packet_id.py获取packet_id.json，运行proto2json.py获取packet_serialization.json。将iridium-bruteforce.py中GetPlayerTokenReq和GetPlayerTokenRsp的packet_id修改为对应版本的。

Get the corresponding version of the proto file(e.g. from [NickTheHuy](https://github.com/NickTheHuy)), run `get_packet_id.py` in [iridium-utils](https://github.com/c2c3vsfac/Iridium-utils) to obtain `packet_id.json`, and run `proto2json.py` to obtain `packet_serialization.json`. Modify the packet_id for `GetPlayerTokenReq` and `GetPlayerTokenRsp` in `iridium-bruteforce.py` to match the corresponding version.

## 解析测速

```
112KB
google protocol buffer parse 1 package(s) cost 0.187425 second(s)
python parse 1 package(s) cost 0.109348 second(s)
c++ parse 1 package(s) cost 30.229842 second(s)

1247
google protocol buffer parse 1 package(s) cost 0.015658 second(s)
python parse 1 package(s) cost 0.000000 second(s)
c++ parse 1 package(s) cost 0.000000 second(s)

2691
google protocol buffer parse 1 package(s) cost 0.015619 second(s)
python parse 1 package(s) cost 0.000000 second(s)
c++ parse 1 package(s) cost 0.062454 second(s)

1490
google protocol buffer parse 4 package(s) cost 0.022784 second(s)
python parse 4 package(s) cost 0.001996 second(s)
c++ parse 4 package(s) cost 0.014014 second(s)

c++的结果是真迷惑，完全相同的思路，它的运行时间怕是按指数增长。换到nlohmann-json，4分钟，我无话可说了。

1557106
google protocol buffer parse 9350 package(s) cost 2.419628 second(s)
python parse 9350 package(s) cost 1.347964 second(s)
```


