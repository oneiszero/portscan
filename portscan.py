#coding:utf-8
#author zeroisone
# 需提前安装/配置好nmap、masscan
# pingfails.txt ping不通结果，自动创建
# results.txt最终扫描结果，自动创建

import os
import time
import shutil
import random
import datetime
import argparse
import ipaddress
import subprocess
import nmap
import asyncio
import requests
import threading
from queue import Queue
import xml.etree.ElementTree as ET
from lxml import etree
from fake_useragent import UserAgent
requests.packages.urllib3.disable_warnings()

masscanpath ="masscan-output" #存放masscan扫描结果文件夹
final_ips = [] #存放扫描结果列表
PORTS = [21, 22, 23, 80, 81, 280, 300, 443, 591, 593, 832, 888, 901, 981, 1010, 1080,
         3306, 5432, 1521, 1433, 9092, 5000, 27017, 6379, 2184, 11211, 2375, 2181, 837,
                   1100, 1241, 1311, 1352, 1434, 1521, 1527, 1582, 1583, 1944, 2082,
                   2082, 2086, 2087, 2095, 2096, 2222, 2301, 2480, 3000, 3128, 3333,
                   4000, 4001, 4002, 4100, 4125, 4243, 4443, 4444, 4567, 4711, 4712,
                   4848, 4849, 4993, 5000, 5104, 5108, 5432, 5555, 5800, 5801, 5802,
                   5984, 5985, 5986, 6082, 6225, 6346, 6347, 6443, 6480, 6543, 6789,
                   7000, 7001, 7002, 7396, 7474, 7674, 7675, 7777, 7778, 8000, 8001,
                   8002, 8003, 8004, 8005, 8006, 8008, 8009, 8010, 8014, 8042, 8069,
                   8075, 8080, 8081, 8083, 8088, 8090, 8091, 8092, 8093, 8016, 8118,
                   8123, 8172, 8181, 8200, 8222, 8243, 8280, 8281, 8333, 8384, 8403,
                   8443, 8500, 8530, 8531, 8800, 8806, 8834, 8880, 8887, 8888, 8910,
                   8983, 8989, 8990, 8991, 9000, 9043, 9060, 9080, 9090, 9091, 9200,
                   9294, 9295, 9443, 9444, 9800, 9981, 9988, 9990, 9999, 10000,
                   10880]
#PORTS_SMALL = [80, 443, 8000, 8080, 8443]

class ScanThread(threading.Thread):
    def __init__(self,q):
        threading.Thread.__init__(self)
        self.q = q
        
    def run(self):
        while not self.q.empty():
            scan_ip = self.q.get()
            try:
                ip = scan_ip.get("ip")
                if scan_ip.get("isprivate"): #内网IP ping验证，ping不通时不扫描
                    if check_alive(ip): 
                        masScan(ip)
                    else: 
                        print('%s ping不通！' % ip)
                else:
                    masScan(ip)
            except Exception as e:
                print(e)
                pass
           
#调用masscan
def masScan(scan_ip):
    temp_ports = [] #设定一个临时端口列表
    print("masscan ....."+scan_ip)
    filename = masscanpath + "/" +scan_ip+".xml"
    if os.name == 'nt': # windows 操作系统
        os.system('masscan.exe ' + scan_ip + ' -p 1-65535 -oX '+ filename + ' --rate 500')
    else: # linux
        os.system('masscan ' + scan_ip + ' -p 1-65535 -oX '+ filename + ' --rate 500')
    
    temp_ports = [] #设定一个临时端口列表
    if os.path.exists(filename):
        sz = os.path.getsize(filename)
        if not sz:
            print(filename +" is empty!")
            final_ips.append(scan_ip+" :masscan端口扫描异常!")
        else:
            try:
                tree = ET.parse(filename)
                root = tree.getroot()
                for host in root.findall("./host/address[@addr='"+scan_ip+"']/.."): # ..获取父标签
                    address = host[0].attrib
                    #ports = host[1].attrib
                    port = host[1][0].attrib
                    if address!='' or port['portid']!='' :
                        temp_ports.append(port['portid'])
                        print("masscan end: "+address['addr']+" "+port['portid'])
                if len(temp_ports) > 50:
                    print(scan_ip+" :扫描开放端口数大于50")#如果端口数量大于50，说明可能存在防火墙，属于误报，清空列表
                    final_ips.append(scan_ip+" :端口扫描开放端口数大于50")
                elif len(temp_ports) == 0:
                    print(scan_ip+" ：masscan端口扫描为零！")
                    final_ips.append(scan_ip+" :masscan端口扫描数为零!")
                else:
                    nmapScan(scan_ip,temp_ports) #小于50则进行端口扫描
                temp_ports = []
            except Exception as e:
                final_ips.append(scan_ip+" :masscan端口扫描xml解析异常!")
                print(e)
                pass
    else:
        print(filename+" is not exists!")

#调用nmap识别服务
def nmapScan(scan_ip,ports):
    nm = nmap.PortScanner()
    portlist = ''
    for port in ports:
        portlist = portlist+port+","
    portlist = portlist.strip(',')
    if portlist.strip()!='':
        print("nmap: "+scan_ip+" "+portlist)
        try:
            ret = nm.scan(scan_ip,portlist,arguments='-Pn,-sS')
            servies = ret['scan'][scan_ip]
            for port in ports:
                service_name = port+" "+ret['scan'][scan_ip]['tcp'][int(port)]['name']
                print(scan_ip + ' : ' + port + ' 端口服务为：' + service_name)
                if port == '80' or 'http' in service_name  or service_name == 'sun-answerbook':
                    if port == '443' or 'https' in service_name or 'https-alt' in service_name:
                        scan_url_port = 'https://' + scan_ip + ':' + str(port)
                        Title(scan_url_port,service_name)
                    else:
                        scan_url_port = 'http://' + scan_ip + ':' + str(port)
                        Title(scan_url_port,service_name)
                else:
                    final_ips.append(scan_ip+':'+str(port)+'\t'+service_name)
                '''  排除特殊端口，其余端口全部当成web 端口进行请求
                elif port !='22' or port !='3306' or port !='3389' or port !='445' or port !='135' or port !='21' or port !='139' or port!= '111':
                    scan_url_port = 'http://' + scan_ip + ':' + str(port)
                    Title(scan_url_port,service_name)
                '''
                
        except Exception as e:
            final_ips.append(scan_ip+" :nmap端口扫描异常!")
            print(e)
            pass
    else:
        print("端口列表为空！")

# 获取网站的web应用程序名和网站标题信息
def Title(url,service_name):
    headers={'User-Agent': UserAgent().random}
    try:
        res = requests.get(url,headers=headers,timeout=3,verify=False)
        split = " - "
        code = res.status_code
        enc = res.encoding
        header = res.headers
        server = header['Server']
        xpoweredby = header['X-Powered-By']
        if code in [200,301,302,404,403,500]:
            try:
                text=res.text.encode(enc).decode('utf-8')
            except:
                try:
                    text=res.text.encode(enc).decode('gbk')
                except Exception as e:
                    print(e)
                    pass
            try:
                html = etree.HTML(text)
                Title = html.findtext('.//title')
                title = Title if Title !=None else 'None'
                if server=='':
                    server = 'None'
            except Exception as e:
                print(e)
                title="None"
            print(url+split+str(code)+split+server+xpoweredby+split+title)
            final_ips.append(url + '\t' + server+xpoweredby + '\t' +title +'\t'+ str(code))

        else:
            final_ips.append(url + '\t' + service_name)
    except Exception as e:
        final_ips.append(url + '\t' + service_name)
        print(e)
        pass

# ping测试ip是否存活
def check_alive(ip):
    result = subprocess.call('ping -w 1000 -n 1 %s' %ip,stdout=subprocess.PIPE,shell=True)
    if result == 0:
        return True
    else:
        with open('pingfails.txt','a+') as f:
            f.write(ip+"\n")
        return False

#启用多线程扫描
def masscanRun(ipDict,thread_nums):
    if not os.path.exists(masscanpath): # 创建临时文件夹，临时存放masscan扫描结果
        os.makedirs(masscanpath)
    queue = Queue(1000*100)
    try:
        count = 0
        for value in ipDict.values(): 
            queue.put(value)
            count += 1
        threads = []
        thread_nums = int(thread_nums)
        if count < thread_nums:
            thread_nums = count
        for i in range(thread_nums):
            threads.append(ScanThread(queue))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    except Exception as e:
        print(e)
        pass

async def socketScan(ip, port): #使用socket连接扫描开发端口
    try:
        reader, writer = await asyncio.open_connection(host=ip, port=port)
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        pass
    else:
        print(ip +':'+str(port))
        final_ips.append(ip+':'+str(port)+'\t'+"端口开放")

async def socketAction(ip, thread_nums):
    ports = [socketScan(ip, port) for port in PORTS] #特定端口扫描
    n = int(thread_nums)
    if n > len(ports):
        n = len(ports)-1
    tasks = [ports[i:i + n] for i in range(0, len(ports), n)]
    for task in tasks:
        await asyncio.wait(task, timeout=5)
#https://wyb0.com/posts/2019/python-coroutine-fast-port-scan/

def socketRun(ipDict,thread_nums):
    
    for value in ipDict.values(): 
        ip = value.get("ip")
        print('开始异步扫描 '+ip+' 开放端口')
        asyncio.run(socketAction(ip, thread_nums))


# 计算IP地址范围
def cal_ip(ip_net): 
    ipDict = {}
    if "/" in ip_net: #子网掩码计算
        try:
            net = ipaddress.ip_network(ip_net, strict=False)
            isPrivate = net.is_private
            for x in net.hosts():
                ip = str(x)
                tmpDict = {"ip":ip,"isprivate":isPrivate}
                ipDict[ip] = tmpDict
        except ValueError:
            print('您输入IP子网格式有误，请检查！')
            exit(0)  
    elif "-" in ip_net:
        tmp=ip_net.split('-')
        if len(tmp) != 2:
            print("IP段范围格式有误！")
            exit(0)
        ipStart = int(ipaddress.ip_address(tmp[0]))
        ipEnd = int(ipaddress.ip_address(tmp[1]))
        ipStartTmp = tmp[0].split('.')
        ipEndTmp = tmp[1].split('.')
        if ipStartTmp[0] != ipEndTmp[0] and ipaddress.ip_address(tmp[1]) < ipaddress.ip_address(tmp[0]):
            print("IP段范围格式有误！")
            exit(0)
        
        startAddr = ipaddress.ip_address(tmp[0])
        isPrivate = startAddr.is_private
        for num in range(ipStart,ipEnd+1):
            if num & 0xff: #过滤掉最后一段为0的IP
                addr =  ipaddress.ip_address(num)
                ip = str(addr)
                tmpDict = {"ip":ip,"isprivate":isPrivate}
                ipDict[ip] = tmpDict
    else:
        try:
            addr = ipaddress.ip_address(ip_net)
            tmpDict = {"ip":ip_net,"isprivate":addr.is_private}
            ipDict[ip_net] = tmpDict
        except ValueError:
            print('您输入IP有误，请检查！')
            exit(0)
    return ipDict

# 读取文本文件IP列表
def read_file_ip(fileName):
    if not os.access(fileName, os.F_OK):
        print(fileName+ "文件不存在或无权限！")
        exit(0)
    try:
        with open(fileName,'r') as f:
            lines = f.readlines()
    except Exception as e:
        print(fileName + "文件读取失败")
        print(e)
        exit(0)

    ipDict = {}
    for line in lines:
        ip = line.strip('\r\n')
        try:
            addr = ipaddress.ip_address(ip)
            if ipDict.get(ip): #字典，去除重复IP
                continue
            else:
                tmpDict = {"ip":ip,"isprivate":addr.is_private}
                ipDict[ip] = tmpDict
        except ValueError:
            print('文件中IP: '+ str(ip) +'格式有误，请检查！')
            continue
    return ipDict

def main():
    parser = argparse.ArgumentParser(description='masscan nmap端口扫描，use: python3 portscan.py -i 192.168.0.1/24 or -f ip.txt')
    parser.add_argument('-i','--ip',help='单个IP或网段，-i 10.0.1.1 or -i 10.0.1.1/24 or -i 10.0.1.0-10.0.2.255')
    parser.add_argument('-f','--file',help='要扫描的IP列表文件')
    parser.add_argument('-t','--thread',type=int,default='5',help='线程参数，默认线程为5')
    parser.add_argument('-s','--socket',action='store_true',help='socket连接方式扫描开放端口')
    args = parser.parse_args()
    if args.ip == None:
        if args.file != None:
            ipDict = read_file_ip(args.file)
        elif args.file == None:
            parser.print_help()
            exit(0)
    else:
        ipDict = cal_ip(args.ip)
    if args.socket:
       socketRun(ipDict,args.thread) #开始socket端口扫描
    else:
        masscanRun(ipDict,args.thread)  #开始masscan扫描
     
if __name__ =='__main__':
    
    start_time = datetime.datetime.now()
    main() #主函数
    if final_ips:
        strtime = time.strftime('%Y-%m-%d-%H-%M-%S',time.localtime())
        fileName = strtime + "-results.txt"
        outfile = open(fileName, "a+" ,encoding="utf-8")
        for tmp_ip in final_ips:
            print(tmp_ip)
            outfile.write(tmp_ip+"\n")
        outfile.close()
        
    spend_time = (datetime.datetime.now() - start_time).seconds
    print('程序共运行了： ' + str(spend_time) + '秒')
    if os.path.exists(masscanpath):#清空文件夹下所有文件
        shutil.rmtree(masscanpath) 
    
