# 基于Netfilter的轻量级防火墙 

## 规则设定
基于源IP，目的IP，源端口，目的端口，协议五个元素构成五元组，另外还要允许掩码设置，标记是否写日志，当规则符合的时候是允许还是禁止。在内核程序中使用链表来存储规则，每条规则对应一个结点，数据结构如下：
```C
// filter rules struct define
typedef struct Node{
  unsigned int sip;
  unsigned int dip;
  unsigned short sport;
  unsigned short dport;
  unsigned short protocol;
  unsigned short sMask;
  unsigned short dMask;
  bool isPermit;
  bool isLog;
  struct Node *next;          //单链表的指针域
}Node,*NodePointer;
```
其中的`sMasK`和`dMask`分别标记源和目标`IP`的掩码，即网络部分位数。这里我直接使用`short`值来表示网络位数，而不是使用标志位来标记是否是掩码，是考虑到在进行数据报进行规则匹配的时候，需要具体的网络位数，而不是仅仅指出是不是掩码方式。

## 文件结构

**kernel**:内核程序,是防火墙的具体处理逻辑，包括钩子的挂载，IP报文的规则判断。
要注意的是，其中使用了一个日志记录文件·`/var/log/myfilter`，我并没有在程序中主动生成，而是先手动创建然后给予程序修改权限。

**user**:用户程序源码,是一个Qt项目。

**dest**:其中`Qt`编译得到的可执行用户程序,注意，这里有一个规则文件`rules.dat`，是过滤规则的配置文件,在程序中会读写这个文件，启动时会尝试读取原有规则。

**关于规则文件**:规则文件是一个自定义文件格式，如`941205696:1000318399:12:1325:6:0:0:1:0`,其中的每一行对应一条规则。和前面给出的数据结构对应，这里把`IP`转换成了无符号整数存储，以`:`分隔分别是源IP、目的IP、源端口、目的端口、协议、源IP网络部分位数（使用掩码方式时）、目的IP网络部分位数、是允许还是禁止、规则匹配时是否写日志。

## 环境
- 虚拟机软件：VMware10 
- 虚拟机：Ubuntu12.04 3.13.0-32
- Qt和Qt Creator: qt-opensource-linux-x64-5.3.1.run
- gcc: 4.6.3

## 如何运行

在`Ubuntu12.04`下，可能需要先更新源，然后安装GCC。

**内核程序**

在`kernel`目录下执行(可以查看`Makefile`文件，拷贝最后一句)

1. `make`，创建了一个`ko`文件，这是我们的内核程序
2. `insmod`挂载，使用`sudo insmod NetfilterFirewall.ko`
3. 创建字符设备，使用`sudo mknod fpNetfilterFirewall c 250 0`

第三步分配设备号250，如果已经被占用，请换其他的设备号。创建成功后，在`/dev/`目录下回出现一个字符设备文件(这里就是`NetfilterFirewall`)。

**用户程序**

先确保挂载内核程序并添加了通信的字符设备后启动用户程序，用户程序将会调用字符设备与内核程序通信，因此需要提升执行权限。

在用户程序目录下，执行`sudo ./NetfilterFirewall`启动程序，如果提示错误，检查是否已经创建了字符设备，或者字符设备创建是否成功。

## 程序执行

用户程序界面

![用户程序](https://github.com/fangnanjun/NetfilterFirewall/raw/master/netfilter.png)

内核程序中使用`prink`打印部分信息，可以使用`dmesg`命令来查看。