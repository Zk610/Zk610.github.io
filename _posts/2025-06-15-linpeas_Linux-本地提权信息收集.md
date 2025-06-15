---
title: Linpeas Linux本地提权信息收集
date: 2025-06-15 01:19:00 +0800
last_modified_at: 2025-06-15 01:19:00 +0800
categories: [工具 , 提权]
tags: [工具 , 提权]
math: true
mermaid: true
---

# 🧩 linpeas.sh 工具介绍

## 一、什么是 linpeas.sh？

**linpeas.sh** 是一个用于 **Linux 本地提权信息收集** 的自动化脚本，由 [PEASS-ng 项目](https://github.com/carlospolop/PEASS-ng) 开发。它可以帮助安全研究人员、红队或渗透测试人员快速定位目标系统中的潜在提权点。

> 📌 linpeas ≈ Linux Privilege Escalation Awesome Script


## 二、工具作用

`linpeas.sh` 并不会直接提权，而是负责**自动发现系统中可能存在的提权线索和漏洞点**，包括但不限于：

* 可滥用的配置
* SUID/SGID 权限文件
* SUDO 权限错误
* 内核漏洞
* Docker/LXC 容器逃逸条件
* 弱配置服务
* 明文凭证与敏感信息泄漏

---

## 三、主要功能模块

| 模块      | 说明                                           |
| ------- | -------------------------------------------- |
| 🔐 权限分析 | 检测 SUDO 权限、SUID/SGID 文件、可写可执行目录等             |
| 🧬 系统信息 | 操作系统、内核版本、语言环境、PATH 配置等                      |
| 🗃 账户信息 | 当前用户、可登录用户、最近登录、passwd/shadow 泄露等            |
| 🔎 敏感信息 | 搜索包含密码、key、token 的文本或文件                      |
| ⚙ 服务/任务 | 检查计划任务、crontab、开机服务、自启脚本等                    |
| 📦 应用漏洞 | 检测已知漏洞内核、可利用的软件服务（如 NFS、Docker）              |
| 🧱 容器环境 | 检测是否在容器中运行，分析逃逸风险（如 Docker 挂载、privileged 模式） |
| 📡 网络信息 | 活跃连接、监听端口、可疑进程等                              |

---

## 四、使用方式

```bash
# 下载 linpeas.sh（推荐使用稳定版本）
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

> ✅ 你也可以直接 curl 执行：

```bash
curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
```
---

## 五、使用建议

* **在实际环境中应获得授权**：请只在合法授权的系统中使用。
* **输出较长**：建议将结果输出到文件以便后续分析，如：

  ```bash
  ./linpeas.sh | tee linpeas_output.txt
  ```
* **配合使用 grep 分析关键词**：如

  ```bash
  grep -i password linpeas_output.txt
  ```

---

## 六、常见应用场景

* 渗透测试中拿到低权限 shell 后用于信息收集
* 安全审计中快速查找弱点
* CTF 中发现提权路径（常用于 Linux 本地提权题目）

---

## 七、相关工具推荐

* **[winpeas.exe](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)**：Windows 本地提权信息收集工具
* **[LES](https://github.com/mzet-/linux-exploit-suggester)**：Linux Exploit Suggester，基于内核版本建议提权漏洞
* **[GTFOBins](https://gtfobins.github.io/)**：Linux 可利用二进制提权方法大全

---
