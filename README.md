<p align="center">
  <img src="static/images/Milkyway-logo.svg" width="100px" alt="afrog">
</p>

<h4 align="center">An innovative vulnerability scanner and Pentest Tool </h4>


## What is Milkyway

MilkyWay 定位是内网扫描工具，它目前结合了机器探活，端口探活，协议识别等功能。协议识别不依赖nmap

## Milkyway Features

1. 信息收集
    * IP 存活探测
    * 端口存活探测
    * 协议识别
        * mysql
        * redis
        * smb
        * ldap
        * to be continued
    * web 探测


2. 爆破功能
   * to be continued


3. 漏洞检测
   * to be continued


4. 漏洞利用
   * to be continued


5. 附带功能
   * 文件导出

编译命令
> go build -ldflags="-s -w " -trimpath main.go

## Usage Tutorial

`milkyway.exe -t 192.168.1.1/24 (端口默认是default, 排名前809个端口)`

`milkyway.exe -t 192.168.1.1/24 -p company (使用公司常用87个端口)`

`milkyway.exe -t 192.168.1.1/24 -p sql (使用数据库常用端口)`

`milkyway.exe -t 192.168.1.1/24 -p samll (使用渗透最常见端口, 排名前12的端口)`

`milkyway.exe -t 192.168.1.1/24 -s socks5://127.0.0.1:1080 (使用socks5代理)`

`milkyway.exe -t 192.168.1.1/24 -c 500 (设置线程池工人数量)`

`milkyway.exe -u https://www.baidu.com (web 探测)`
### Running Picture



![img.png](./static/images/running_picture1.png)

![img.png](./static/images/running_picture2.png)

![img.png](./static/images/running_picture3.png)
