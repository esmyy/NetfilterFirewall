# 基于Netfilter的轻量级防火墙 

分成两个部分，一个是内核程序部分，一个是用户程序。

## 环境


## 如何运行

在`Ubuntu12.04`下，可能需要先更新源，然后安装G++,GCC。

**内核程序**

在`NetfilterFirewall`目录下执行

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