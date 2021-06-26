# portscan
masscan+nmap扫描，python socket端口扫描

```
usage: portscan.py [-h] [-i IP] [-f FILE] [-t THREAD] [-s]

masscan nmap端口扫描，use: python3 portscan.py -i 192.168.0.1/24 or -f ip.txt

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        单个IP或网段，-i 10.0.1.1 or -i 10.0.1.1/24 or -i
                        10.0.1.0-10.0.2.255
  -f FILE, --file FILE  要扫描的IP列表文件
  -t THREAD, --thread THREAD
                        线程参数，默认线程为5
  -s, --socket          socket连接方式扫描开放端口

```

## 功能描述
* 使用masnmapscan-V1.0在多线程扫描时，会造成重复扫描，参考此脚本进行改进完善
  masscan扫描每个ip后生成单个ip的扫描结果，立即开始nmap扫描
  
  ```
  masscan 127.0.0.1
  masscan 127.0.0.2  
                   nmap 127.0.0.1
                   nmap 127.0.0.2
  masscan 127.0.0.3
  masscan 127.0.0.4
                   nmap 127.0.0.3
                   nmap 127.0.0.4
  ```
* 自动判断内网ip，内网ip ping不通时，默认不扫描端口
* 支持单个ip/网段、网段区间范围、文本列表扫描
* 对端口识别为web服务的，进行http/https请求，并获取端口
* socket方式扫描默认探测161个常见端口，扫描全端口需修改PORTS
* 扫描结果保存在：日期+results.txt中，“pingfails.txt”保存ping不通结果


## Linux安装masscan、nmap

**apt安装（版本较低）** 

```
apt install nmap    #安装nmap
apt install masscan #安装masscan

```

**源码安装** 

```
# masscan
sudo apt-get --assume-yes install git make gcc
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
sudo make install

#nmap
sudo apt-get install g++
wget https://nmap.org/dist/nmap-7.91.tar.bz2
bzip2 -cd nmap-7.91.tar.bz2 | tar xvf -
cd nmap-7.91
./configure
make
sudo make install

```

## 参考
https://github.com/hellogoldsnakeman/masnmapscan-V1.0
https://wyb0.com/posts/2019/python-coroutine-fast-port-scan/





