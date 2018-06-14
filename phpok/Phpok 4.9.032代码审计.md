# Phpok 4.9.032

## 任意文件上传（upload vulnerability）

漏洞代码在framework/admin/modulec_control.php 642行。

![1](phpok/1.png)

这里直接将解压的文件存入/data/cache中，将phpinfo.php压缩到phpinfo.php.zip,点击设置，模块管理。

![2](phpok/2.png)

点击模块导入

![3](phpok/3.png)

上传

![4](phpok/4.png)

成功写入

![5](phpok/5.png)

![6](phpok/6.png)

## 任意文件删除 （Any file deletion vulnerability）

漏洞位置在于framework/admin/tpl_control.php

![7](phpok/7.png)

点击设置-风格管理

![8](phpok/8.png)

点击文件管理

![9](phpok/9.png)

点击文件删除

![10](phpok/10.png)

抓包修改`../../../phpok/index.txt`。 ![11](phpok/11.gif)