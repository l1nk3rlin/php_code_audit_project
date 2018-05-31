---
title: YzmcmsXss
date: 2018-04-11 12:51:50
tags:
---

YZMCMS v3.7.1最新版xss漏洞

YZMCMS v3.7.1 latest xss vulnerability

这个xss存在于v3.7.1中的微信模块

This xss exists in the WeChat module in v3.7.1

我们可以在YzmCMS-V3.7.1/application/wechat/controller/index.class.php第36-39行找到相关代码

We can find the relevant code in YzmCMS-V3.7.1/application/wechat/controller/index.class.php, lines 36-39

![1](/YzmcmsXss/1.png)

第37行通过get方式传入一个echostr，然后在39行没有进行任何过滤的情况下，直接将参数echo出来。

Line 37 passes an echostr through get, then echoes the argument directly on line 39 without any filtering.

我们在页面找到功能点，构造POC为：`echostr=aaa"></a></span><script>alert(1)</script><a>`，发现成功执行。

We find the function point on the page and construct the POC as: `echostr=aaa"></a></span><script>alert(1)</script><a>` and find that the POC is executed successfully.

![2](/YzmcmsXss/2.png)





