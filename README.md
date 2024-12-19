[English README](https://github.com/polite-007/Milkyway/README_EN.md)
<p align="center">
  <img src="static/images/Milkyway-logo.svg" width="100px" alt="milkyway">
</p>

[![Latest release](https://img.shields.io/github/v/release/polite-007/Milkyway)](https://github.com/polite-007/Milkyway/releases/latest)![GitHub Release Date](https://img.shields.io/github/release-date/polite-007/Milkyway)![GitHub All Releases](https://img.shields.io/github/downloads/polite-007/Milkyway/total)[![GitHub issues](https://img.shields.io/github/issues/polite-007/Milkyway)](https://github.com/polite-007/Milkyway/issues)

> 本工具仅供安全测试人员运用于授权测试, 禁止用于未授权测试, 违者责任自负

## 什么是Milkyway

一款全方位扫描工具，具备高效的机器探活，端口探活，协议识别，指纹识别，漏洞扫描等功能,
* 纯go实现的协议识别
* 丰富的扫描模式
* 支持端口扫描的乱序 (目标越大，速度越块，准确度越高)

> 如果你觉得这款工具不错的话，求star~

## Milkyway能做什么

1. 信息收集
    * IP & 端口存活探测
    * WEB 探测
    * 协议识别 (`mysql`,`redis`,`smb`,`ldap`,`ssh`,`vnc`,`ftp`,`smtp`, `rdp`)
2. 爆破功能
   * `ssh`,`mysql`,`redis`,`vnc`
   * to be continued
3. 漏洞检测
   * `redis`未授权
   * 永恒之蓝/永恒之黑
   * `nuclei`漏洞引擎
   * 通过`tags`,`id`来选择poc
4. 额外功能
   * 日志实时打印
   * 自定义指纹文件加载
   * 自定义`poc`预加载目录或文件
   * `http`/`socks5`代理
   * 支持`fofa`语句,目标从`fofa`拉取
   * 支持`url`的输入
   * 支持目标从文件提取

### 进阶参数
* `--finger-file ` 自定义web指纹加载
* `--scan-random ` 端口扫描是否随机
* `--full-scan   ` 对开放的端口进行全协议识别,默认只进行特定端口的协议识别
* `--verbose     ` 打印协议的详细信息
* `--no-match    ` 漏洞扫描前的指纹规则不进行匹配
* `--poc-file    ` 自定义`nuclei poc`文件/目录
* `--fofa-query  ` 使用`fofa`语句提取目标 `当使用fofa语句导入目标时，系统环境变量FOFA_KEY必须设置成的你的fofa-key`

### 基本参数使用

`milkyway.exe -t 192.168.1.1/24 (端口默认是default, 排名前809个端口)`

`milkyway.exe --fofa-query 'domain=baidu.com'` (fofa语句提取目标)

`milkyway.exe -t 192.168.1.1/24 -s socks5://127.0.0.1:1080` (使用socks5代理)

`milkyway.exe -t 192.168.1.1/24 -c 500` (设置线程池工人数量)

### 演示案例

1. 利用fofa进行外网全端口打点,并且使用乱序扫描
   
   `milkyway.exe --fofa-query 'domain=fofa.info||host=fofa.info' -p all --no-ping --scan-random`
   ![img.png](./static/images/running_picture6.png)

2. 设置1000并发量使用无序扫描内网所有端口

   `milkyway.exe -t 192.168.1.0/24 -p all --scan-random -c 1000 --no-ping`
   ![img.png](./static/images/running_picture7.png)

### 进阶参数使用

`milkyway.exe -t 192.168.1.1/24 -p company` (使用公司常用87个端口)

`milkyway.exe -t 192.168.1.1/24 -p small --full-scan` (对前12个端口进行全协议识别)

`milkyway.exe -t 192.168.1.1/24 --no-ping` (跳过icmp扫描)

`milkyway.exe -t 192.168.1.1/24 --finger-file ./your_file` (自定义指纹文件)

`milkyway.exe -t 192.168.1.1/24 --verbose` (打印协议详细信息)

`milkyway.exe -t 192.168.1.1/24 --no-match` (漏洞扫描不进行指纹匹配,即下发全量)

`milkyway.exe -t 192.168.1.1/24 --poc-file ./your_file` (自定义漏洞目录)

`milkyway.exe -t 192.168.1.1/24 --poc-tags cve,cnvd` (指定多个poc标签)

> `sql`: 常用数据库端口, `small`: 常用前12个端口, `all`: 全端口

### Running Picture

![img.png](./static/images/running_picture1.png)

![img.png](./static/images/running_picture2.png)

![img.png](./static/images/running_picture5.png)

![img.png](./static/images/running_picture4.png)

**特别鸣谢～FOFA官方**

Milkyway 已加入 FOFA [共创者计划](https://fofa.info/development)，感谢 FOFA 提供的账号支持。

<img width="318" alt="image" src="https://user-images.githubusercontent.com/67818638/210543196-b76f6808-b5dd-4933-9451-0c3217dca8f5.png">

# 参考项目
https://github.com/shadow1ng/fscan

https://github.com/EdgeSecurityTeam/EHole

https://github.com/chainreactors/neutron
