# linux server syscheck
1,适用范围

    该脚本可在redhat6,redhat7,centos6,centos7,sles11,sles12系列上跑
2,脚本作用

    脚本用来抓取系统数据,做巡检系统
3,脚本使用

    将脚本拷贝至需要进行巡检的主机上,直接执行即可:
```
$ bash linux_syscheck.sh
```
4,数据存放
脚本跑完后,巡检数据会以${ip}.tar.gz的形式存放在/tmp目录下
