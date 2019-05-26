#!/bin/bash
# Date: 2017-09-12
# Location: Shenzhen
# Description: Used for quarterly system health check

# Run as root
if [ $(id -u) -ne '0' ]; then
	echo "Please run as root!"
	exit 1
fi

if [ ! -f "/sbin/ip" ]; then
	echo "Command /sbin/ip not found!"
	exit 2
fi

# Clear the screen
clear

curDate=$(date +%Y%m%d)

# 创建并进入以IP命名的信息收集目录
ip_addr=$(/sbin/ip addr | grep 'inet ' | grep -v '127.0.0.' | \
        egrep -o 'inet (addr:)?[.0-9]+' | \
        awk '{print $NF}' | head -n1)

if [ -z "${ip_addr}" ]; then
	echo "No ip_addr!"
	exit 3
fi

dataDir="/tmp"
targetDir=${dataDir}/${ip_addr}

if [ ! -d ${targetDir} ]; then
    mkdir -p ${targetDir}
else
    echo "Target directory already exists!"

    read -p "Backup and create a new one[Y/n]: " choice
    case "${choice}" in
        [Yy] | [yY][Ee][Ss])
            tmpdir=$(mktemp -d --tmpdir=/tmp ${curDate}.XXXX)
            mv ${targetDir} ${tmpdir}
            mkdir -p ${targetDir}
            echo -e "Old directory backuped!\n" 
            ;;  
        *)
            echo -e "Checking stopped!\n"
            exit 1
            ;;  
    esac
fi

cd ${targetDir}

# 通过下列命令获取检测系统所需的信息
# 统一使用英文字符，方便收集信息
export LANG="en_US.UTF-8"
echo "Start scanning......"

stderr="stderr.txt"
tmperr="tmperr.txt"

# functions
cmd_head() {
    echo -e "#$1\n" >> ${stderr}
}

dot_line() {
    echo -e "------------------------------------------\n" >> ${stderr}
}

# store empty tmp files
garbageDir="garbage"
[ ! -d ${garbageDir} ] && mkdir ${garbageDir}

if_empty_mv() {
    if [ ! -s "$1" ]; then
        /bin/mv -f $1 ${garbageDir} 2> /dev/null
    fi
}

gc() {
    /bin/mv -f ${tmperr} ${garbageDir} 2> /dev/null
}

get_data() {
    ${cmd} 1> ${targetFile} 2> ${tmperr}
    if [ $? -ne 0 ]; then
        cmd_head "$1"
        cat ${tmperr} >> ${stderr}
        dot_line
    fi
    gc
    if_empty_mv $2
}

save_file() {
    get_data "${cmd}" "${targetFile}"
}    

rename_txt() {
    for a in $(ls *${targetFile}* 2> /dev/null)
    do
        mv $a{,.txt}
    done
}

## 巡检时间
cmd='eval date "+%Y-%m-%d %H:%M:%S"'
targetFile="date.txt"
save_file

## 系统rpm包
cmd="rpm -qa"
targetFile="rpm_-qa.txt"
save_file

## dmesg
cmd="dmesg"
targetFile="dmesg.txt"
save_file

########## Hardware ##########
## 主板信息
cmd="dmidecode"
targetFile="dmidecode.txt"
save_file

## 光纤卡、RAID卡信息
cmd="lspci"
targetFile="lspci.txt"
save_file

## CPU信息
cmd="cat /proc/cpuinfo"
targetFile="cpuinfo.txt"
save_file

## 内存信息
cmd="cat /proc/meminfo"
targetFile="meminfo.txt"
save_file

## 磁盘状态
cmd="cat /proc/diskstats"
targetFile="diskstats.txt"
save_file

## CPU中断
cmd="cat /proc/interrupts"
targetFile="interrupts.txt"
save_file

## 硬件端口
cmd="cat /proc/ioports"
targetFile="ioports.txt"
save_file


########## Software ##########
## 查看群集状态
# cman cluster
cmd="service cman status"
targetFile="service_cman_status.txt"
save_file

cmd="clustat -l"
targetFile="clustat_-l.txt"
save_file

# pacemaker cluster
cmd="systemctl status pcsd"
targetFile="systemctl_status_pcsd.txt"
save_file

cmd="pcs status"
targetFile="pcs_status.txt"
save_file

## 查看openssh版本
cmd="rpm -qa | grep openssh"
targetFile="openssh.txt"
save_file

## 查看当前所有进程
cmd="ps -ef"
targetFile="ps_-ef.txt"
save_file

cmd="ps -A -o stat,ppid,pid,cmd"
targetFile="ps_-A_-o_ppidstat.txt"
save_file

## 网络端口
cmd="netstat -antup"
targetFile="netstat_-antup.txt"
save_file

cmd="lsof -i -n"
targetFile="lsof_-i_-n.txt"
save_file


##########    OS    ##########
## 系统版本信息
# rhel && centos
cmd="cat /etc/redhat-release"
targetFile="redhat-release.txt"
save_file

# sles
cmd="cat /etc/SuSE-release"
targetFile="SuSE-release.txt"
save_file

# common
cmd="cat /etc/issue"
targetFile="etc_issue.txt"
save_file

## 系统内核版本
cmd="uname -a"
targetFile="uname_-a.txt"
save_file

## gcc版本
cmd="gcc --version"
targetFile="gcc_version.txt"
save_file

## 系统运行时间
cmd="uptime"
targetFile="uptime.txt"
save_file

## 系统安装时间
cmd="rpm -qi $(rpm -qf /bin/ls)"
targetFile="rpm_-qi_ls.txt"
save_file

## 系统模块
cmd="lsmod"
targetFile="lsmod.txt"
save_file

cmd="cp -a /etc/modprobe.* ./"
targetFile="empty"
save_file

## IP及流量信息
cmd="ifconfig -a"
targetFile="ifconfig_-a.txt"
save_file

cmd="ip addr"
targetFile="ip_addr.txt"
save_file

# rhel
cmd="cp /etc/sysconfig/network-scripts/ifcfg-* ./"
targetFile="ifcfg-"
save_file
rename_txt

# sles 
cmd="cp /etc/sysconfig/network/ifcfg-* ./"
targetFile="ifcfg-"
save_file
rename_txt

cmd="cat /etc/sysconfig/network/routes"
targetFile="routes.txt"
save_file

## 网卡绑定情况
# bonding
cmd="cp /proc/net/bonding/bond* ./"
targetFile="bond"
save_file

if [[ -e bond* ]]; then
    rename_txt
fi

# teaming
cmd="teamdctl team0 state"
targetFile="team0_state.txt"
save_file

cmd="teamdctl team1 state"
targetFile="team1_state.txt"
save_file

## udev规则
cmd="cp /etc/udev/rules.d/*net.rules ./"
targetFile="net.rules"
save_file
rename_txt

## 路由表
cmd="route -n"
targetFile="route_-n"
save_file

## 主机名和网络状态
cmd="hostname"
targetFile="hostname.txt"
save_file

cmd="cat /etc/sysconfig/network"
targetFile="network.txt"
save_file

# rhel7 && sles12
cmd="hostnamectl"
targetFile="hostnamectl.txt"
save_file

# sles
cmd="cat /etc/HOSTNAME"
targetFile="HOSTNAME.txt"
save_file

## 主机名和网络状态
# sles
cmd="rckdump status"
targetFile="kdump_status_sles.txt"
save_file

# rhel & centos
cmd="service kdump status"
targetFile="kdump_status_rhel.txt"
save_file

## hosts绑定信息
cmd="cat /etc/hosts"
targetFile="hosts.txt"
save_file

## host.conf信息
cmd="cat /etc/host.conf"
targetFile="host.conf.txt"
save_file

## iscsi共享存储连接状态
cmd="iscsiadm -m session -i"
targetFile="iscsiadm_-m_session_-i.txt"
save_file

## 磁盘信息
cmd="fdisk -l"
targetFile="fdisk_-l.txt"
save_file

## lvm目录
cmd="cp -r /etc/lvm/ ./"
targetFile="etc_lvm.txt"
save_file

## pvs
cmd="pvs"
targetFile="pvs.txt"
${cmd} &> ${tmperr}
if grep -q "PV" "${tmperr}"; then
    ${cmd} 1> ${targetFile} 2> /dev/null
elif grep -q "open failed" "${tmperr}"; then
    cmd_head ${cmd}
    grep "open failed" "${tmperr}" >> ${stderr}
    dot_line
fi
gc

## vgs
cmd="vgs"
targetFile="vgs.txt"
lvm_err="No volume groups found"
${cmd} &> ${tmperr}
if grep -qv "${lvm_err}" "${tmperr}"; then
    vgs 1> ${targetFile} 2> /dev/null
else
    cmd_head ${cmd}
    echo "${lvm_err}" >> ${stderr}
    dot_line
fi
gc

## lvs
cmd="lvs"
targetFile="lvs.txt"
${cmd} &> ${tmperr}
if grep -qv "${lvm_err}" "${tmperr}"; then
    lvs 1> ${targetFile} 2> /dev/null
else
    cmd_head ${cmd}
    echo "${lvm_err}" >> ${stderr}
    dot_line
fi
gc

## soft raid
cmd="cat /proc/mdstat"
targetFile="mdstat.txt"
save_file

## 磁盘空间信息
cmd="df -hP"
targetFile="df_-hP.txt"
save_file

## Inode使用情况
cmd="df -hiTP"
targetFile="df_-hiTP.txt"
save_file

## 查看挂载信息
cmd="cat /proc/mounts"
targetFile="proc_mounts.txt"
save_file

## 多路径信息
cmd="multipath -ll"
targetFile="multipath_-ll.txt"
save_file

cmd="cat /etc/multipath/bindings"
targetFile="bindings.txt"
if ${cmd} &> /dev/null; then
    save_file
fi

cmd="powermt display dev=all"
targetFile="powermt_display_dev.txt"
save_file

cmd="ls -l /dev/ | grep -i emcpower"
targetFile="dev_emcpower.txt"
if ${cmd} &> /dev/null; then
    save_file
fi

## 系统负载和CPU资源占用
cmd="top -b -d 2.5 -n 1"
targetFile="top.txt"
save_file

## 各CPU负载
cmd="mpstat -P ALL 1 10"
targetFile="mpstat_-P_-ALL.txt"
save_file

## 磁盘io
cmd="iostat -xdc 1 10"
targetFile="iostat_-xdc.txt"
save_file

## 性能参数
cmd="cp /var/log/sa/* ./"
targetFile="empty"
save_file

## 物理内存使用情况
cmd="free -m"
targetFile="free_-m.txt"
save_file

## 系统用户信息
cmd="cat /etc/passwd"
targetFile="passwd.txt"
save_file

## 系统组信息
cmd="cat /etc/group"
targetFile="group.txt"
save_file

## 用户口令复杂性
cmd="cat /etc/login.defs"
targetFile="login.defs.txt"
save_file

## 口令复杂度函数
# rhel
cmd="cat /etc/pam.d/system-auth"
targetFile="system-auth.txt"
save_file

# sles
cmd="cat /etc/pam.d/common-password"
targetFile="common_password.txt"
save_file

cmd="cat /etc/pam.d/common-auth"
targetFile="common_auth.txt"
save_file

## ssh远程登录
cmd="cat /etc/ssh/sshd_config"
targetFile="sshd_config.txt"
save_file

## 登录时长
cmd="ac -p"
targetFile="ac_-p.txt"
save_file

## 用户登录情况
cmd="last"
targetFile="last.txt"
save_file

cmd="lastb"
targetFile="lastb.txt"
save_file

day=$(date +%Y%m%d -d "3 month ago")
targetFile="lastb3.txt"
diff <(lastb) <(lastb -t ${day}000000) | awk '$1=="<"{print $0}' | sed 's/^< //g' > ${targetFile}
gc

## SELinux配置
cmd="getenforce"
targetFile="getenforce.txt"
save_file

cmd="cat /etc/sysconfig/selinux"
targetFile="selinux.txt"
save_file

## 防火墙配置
# rhel6
cmd="service iptables status"
targetFile="service_iptables_status.txt"
save_file

cmd="iptables -nL"
targetFile="iptables_-nL.txt"
save_file

# rhel7
cmd="systemctl status firewalld"
targetFile="systemctl_status_firewalld.txt"
save_file

cmd="firewall-cmd --list-all-zones"
targetFile="firewall_cmd_list_all_zones.txt"
save_file

# sles
cmd="SuSEfirewall2 status"
targetFile="SuSEfirewall2_status.txt"
save_file

## 日志信息
cmd="cp /var/log/messages ./"
targetFile="messages"
save_file
rename_txt

# rhel
cmd="cp /var/log/secure ./"
targetFile="secure"
save_file
rename_txt

# sles
cmd="cp /var/log/warn ./"
targetFile="warn"
save_file
rename_txt

echo "..."
echo

# 日志审核
if [ -e /etc/rsyslog.conf ]; then
    cmd="cat /etc/rsyslog.conf"
    targetFile="rsyslog.conf.txt"
    save_file

    cmd="cat /etc/sysconfig/rsyslog"
    targetFile="rsyslog.txt"
    save_file
else
    cmd="cat /etc/syslog.conf"
    targetFile="syslog.conf.txt"
    save_file

    cmd="cat /etc/sysconfig/syslog"
    targetFile="syslog.txt"
    save_file
fi

## 系统自带审核功能
cmd="service auditd status"
targetFile="service_auditd_status.txt"
save_file

## 审计日志
cmd="cat /var/log/audit/audit.log"
targetFile="audit.log.txt"
save_file

## 日志转储策略
cmd="cat /etc/logrotate.conf"
targetFile="logrotate.conf.txt"
save_file

cmd="cp -r /etc/logrotate.d ./"
targetFile="emtpy"
save_file

## 时间服务器地址
# rhel6 && sles
cmd="ntpq -p"
targetFile="ntpq_-p.txt"
save_file

cmd="cat /etc/ntp.conf"
targetFile="ntp.conf.txt"
save_file

# rhel7
cmd="chronyc sources"
targetFile="chronyc_sources.txt"
save_file

cmd="cat /etc/chrony.conf"
targetFile="chrony.conf.txt"
save_file

## 系统运行模式
# sles11 && rhel6
cmd="runlevel"
targetFile="runlevel.txt"
save_file

# rhel7 && sles12
cmd="systemctl list-units --type target"
targetFile="systemctl_list_units_target.txt"
save_file

## 开机启动的服务
# rhel6 && sles11
cmd="chkconfig --list"
targetFile="chkconfig_--list.txt"
save_file

# rhel7 && sles12
cmd="systemctl list-unit-files"
targetFile="chkconfig_--list.txt"
save_file

## 所有系统服务当前状态
rhel6 && sles11
cmd="service --status-all"
targetFile="service_--status-all.txt"
save_file

# rhel7 && sles12
cmd="systemctl list-units --type=service"
targetFile="systemctl_list-units.txt"
save_file

## 系统启动相关
# rhel6 && sles11
cmd="cat /etc/inittab"
targetFile="inittab.txt"
save_file

# rhel7 && sles12
cmd="cat /etc/systemd/system/default.targets"
targetFile="default.targets.txt"
save_file

# rhel
cmd="cp -r /etc/rc.d/init.d ./"
targetFile="empty"
save_file

# sles
cmd="cp -r /etc/init.d ./"
targetFile="empty"
save_file

## 系统登录时自动执行的命令
# rhel
cmd="cat /etc/rc.d/rc.local"
targetFile="rc.local.txt"
save_file

# sles
cmd="cat /etc/init.d/boot.local"
targetFile="etc_initd_boot_local.txt"
save_file

## 用户登录时加载的变量
# rhel
cmd="cat /etc/profile"
targetFile="etc_profile.txt"
save_file

cmd="cat /etc/bashrc"
targetFile="etc_bashrc.txt"
save_file

cmd="cat /root/.bash_profile"
targetFile="root_bash_profile.txt"
save_file

cmd="cat /root/.bashrc"
targetFile="root_bashrc.txt"
save_file

# sles
cmd="cat /etc/bash.bashrc"
targetFile="etc_bash_bashrc.txt"
save_file


## 开机自动挂载的分区
cmd="cat /etc/fstab"
targetFile="fstab.txt"
save_file

## grub配置信息
cmd="cat /boot/grub/grub.conf"
targetFile="boot_grub.conf.txt"
save_file

cmd="cat /etc/grub.conf"
targetFile="etc_grub.conf.txt"
save_file

cmd="cat /boot/grub2/grub.cfg"
targetFile="boot_grub2.cfg.txt"
save_file

cmd="cat /etc/grub2.cfg"
targetFile="etc_grub2.cfg.txt"
save_file

cmd="cat /boot/grub/menu.lst"
targetFile="boot_grub_menulst.txt"
save_file

cmd="cp -r /boot/efi/EFI/ ./"
targetFile="empty"
save_file

## 系统资源限制
cmd="ulimit -a"
targetFile="ulimit_-a.txt"
save_file

cmd="cat /etc/security/limits.conf"
targetFile="limits.conf.txt"
save_file

cmd="cp -a /etc/security/limits.d ./"
targetFile="empty"
save_file

## 内核参数设置
cmd="sysctl -a"
targetFile="sysctl_-a.txt"
save_file

cmd="cat /etc/sysctl.conf"
targetFile="sysctl.conf.txt"
save_file

## rngd服务
cmd="cat /proc/sys/kernel/random/entropy_avail"
targetFile="entropy_avail.txt"
save_file

## 各个网卡的设置信息
for a in $(ip a | grep '^[0-9]' | grep -v 'lo' | awk -F'[ :]+' '{print $2}')
do
    cmd="ethtool ${a}"
    targetFile="ethtool_${a}.txt"
    save_file
done

## 计划任务
cmd="cp -a /etc/cron.* ./"
targetFile="empty"
save_file

cmd="cp -a /var/spool/cron/* ./"
targetFile="empty"
save_file

cmd="cat /etc/crontab"
targetFile="crontab.txt"
save_file

cmd="crontab -l"
targetFile="crontab_-l.txt"
save_file

########## CVE check ##########
shellshock_test() {
VUNERABLE=false;
CVE20146271="$(env 'x=() { :;}; echo vulnerable' 'BASH_FUNC_x()=() { :;}; echo vulnerable' bash -c "echo test" 2>&1 )"

CVE20147169=$(cd /tmp 2>&1; rm -f /tmp/echo 2>&1; env 'x=() { (a)=>\' bash -c "echo uname" 2>&1; cat /tmp/echo 2>&1; rm -f /tmp/echo 2>&1 )

if [[ "$CVE20146271" =~ "vulnerable" ]]
then
    echo "This system is vulnerable to CVE-2014-6271 <https://access.redhat.com/security/cve/CVE-2014-6271>"
    VUNERABLE=true;
elif [[ "$CVE20146271" =~ "bash: error importing function definition for 'x'" ]]
then
    echo "This system does not have to most up to date fix for CVE-2014-6271 <https://access.redhat.com/security/cve/CVE-2014-6271>.  Please refer to 'https://access.redhat.com/articles/1200223' for more information"
else
	echo "This system is safe from CVE-2014-6271 <https://access.redhat.com/security/cve/CVE-2014-6271>"
fi

if [[ "$CVE20147169" =~ "Linux" ]]
then
    echo "This system is vulnerable to CVE-2014-7169 <https://access.redhat.com/security/cve/CVE-2014-7169>"
    VUNERABLE=true;
else
	echo "This system is safe from CVE-2014-7169 <https://access.redhat.com/security/cve/CVE-2014-7169>"
fi

if [[ "$VUNERABLE" = true ]]
then
	echo "Please run 'yum update bash'.  If you are using satellite or custom repos you need to update the channel with the latest bash version first before running 'yum update bash'.  Please refer to 'https://access.redhat.com/articles/1200223' for more information"
fi
}

GHOST_test() {
echo "Installed glibc version(s)"
rv=0
for glibc_nvr in $( rpm -q --qf '%{name}-%{version}-%{release}.%{arch}\n' glibc ); do
    glibc_ver=$( echo "$glibc_nvr" | awk -F- '{ print $2 }' )
    glibc_maj=$( echo "$glibc_ver" | awk -F. '{ print $1 }')
    glibc_min=$( echo "$glibc_ver" | awk -F. '{ print $2 }')
    
    echo -n "- $glibc_nvr: "
    if [ "$glibc_maj" -gt 2   -o  \
        \( "$glibc_maj" -eq 2  -a  "$glibc_min" -ge 18 \) ]; then
        # fixed upstream version
        echo 'not vulnerable'
    else
        # all RHEL updates include CVE in rpm %changelog
        if rpm -q --changelog "$glibc_nvr" | grep -q 'CVE-2015-0235'; then
            echo "not vulnerable"
        else
            echo "vulnerable"
            rv=1
        fi
    fi
done

if [ $rv -ne 0 ]; then
    cat <<EOF

This system is vulnerable to CVE-2015-0235. <https://access.redhat.com/security/cve/CVE-2015-0235>
Please refer to <https://access.redhat.com/articles/1332213> for remediation steps
EOF
fi

# exit $rv
return $rv
}

cve_2017_1000366_2() {
# Warning! Be sure to download latest version of this script from its primary source:
# https://access.redhat.com/security/vulnerabilities/stackguard
# DO NOT blindly trust any internet sources and NEVER do `curl something | bash`!

# Checking against the list of vulnerable packages is necessary because of the way how features
# are back-ported to older versions of packages in various channels.

VULNERABLE_VERSIONS=(
    'glibc-2.5-18'
    'glibc-2.5-24'
    'glibc-2.5-34'
    'glibc-2.5-42'
    'glibc-2.5-49'
    'glibc-2.5-58'
    'glibc-2.5-65'
    'glibc-2.5-81'
    'glibc-2.5-107'
    'glibc-2.5-118'
    'glibc-2.5-123'
    'glibc-2.17-79.ael7b_1'
    'glibc-2.17-79.ael7b_1.4'
    'glibc-2.5-18.el5_1.1'
    'glibc-2.5-24.el5_2.2'
    'glibc-2.5-24.el5_2.3'
    'glibc-2.5-34.el5_3.1'
    'glibc-2.5-34.el5_3.2'
    'glibc-2.5-34.el5_3.3'
    'glibc-2.5-34.el5_3.4'
    'glibc-2.5-42.el5_4.2'
    'glibc-2.5-42.el5_4.3'
    'glibc-2.5-42.el5_4.4'
    'glibc-2.5-42.el5_4.5'
    'glibc-2.5-49.el5_5.2'
    'glibc-2.5-49.el5_5.4'
    'glibc-2.5-49.el5_5.5'
    'glibc-2.5-49.el5_5.6'
    'glibc-2.5-49.el5_5.7'
    'glibc-2.5-58.el5_6.2'
    'glibc-2.5-58.el5_6.3'
    'glibc-2.5-58.el5_6.4'
    'glibc-2.5-58.el5_6.5'
    'glibc-2.5-58.el5_6.6'
    'glibc-2.5-65.el5_7.1'
    'glibc-2.5-65.el5_7.3'
    'glibc-2.5-81.el5_8.1'
    'glibc-2.5-81.el5_8.2'
    'glibc-2.5-81.el5_8.4'
    'glibc-2.5-81.el5_8.7'
    'glibc-2.5-107.el5_9.1'
    'glibc-2.5-107.el5_9.4'
    'glibc-2.5-107.el5_9.5'
    'glibc-2.5-107.el5_9.6'
    'glibc-2.5-107.el5_9.7'
    'glibc-2.5-107.el5_9.8'
    'glibc-2.5-118.el5_10.2'
    'glibc-2.5-118.el5_10.3'
    'glibc-2.5-123.el5_11.1'
    'glibc-2.5-123.el5_11.3'
    'glibc-2.12-1.7.el6_0.3'
    'glibc-2.12-1.7.el6_0.4'
    'glibc-2.12-1.7.el6_0.5'
    'glibc-2.12-1.7.el6_0.8'
    'glibc-2.12-1.25.el6'
    'glibc-2.12-1.25.el6_1.3'
    'glibc-2.12-1.47.el6'
    'glibc-2.12-1.47.el6_2.5'
    'glibc-2.12-1.47.el6_2.9'
    'glibc-2.12-1.47.el6_2.12'
    'glibc-2.12-1.47.el6_2.13'
    'glibc-2.12-1.47.el6_2.15'
    'glibc-2.12-1.47.el6_2.17'
    'glibc-2.12-1.80.el6'
    'glibc-2.12-1.80.el6_3.3'
    'glibc-2.12-1.80.el6_3.4'
    'glibc-2.12-1.80.el6_3.5'
    'glibc-2.12-1.80.el6_3.6'
    'glibc-2.12-1.80.el6_3.7'
    'glibc-2.12-1.107.el6'
    'glibc-2.12-1.107.el6_4.2'
    'glibc-2.12-1.107.el6_4.4'
    'glibc-2.12-1.107.el6_4.5'
    'glibc-2.12-1.107.el6_4.6'
    'glibc-2.12-1.107.el6_4.7'
    'glibc-2.12-1.107.el6_4.9'
    'glibc-2.12-1.132.el6'
    'glibc-2.12-1.132.el6_5.1'
    'glibc-2.12-1.132.el6_5.2'
    'glibc-2.12-1.132.el6_5.3'
    'glibc-2.12-1.132.el6_5.4'
    'glibc-2.12-1.132.el6_5.5'
    'glibc-2.12-1.132.el6_5.7'
    'glibc-2.12-1.132.el6_5.8'
    'glibc-2.12-1.149.el6'
    'glibc-2.12-1.149.el6_6.4'
    'glibc-2.12-1.149.el6_6.5'
    'glibc-2.12-1.149.el6_6.7'
    'glibc-2.12-1.149.el6_6.9'
    'glibc-2.12-1.149.el6_6.11'
    'glibc-2.12-1.166.el6'
    'glibc-2.12-1.166.el6_7.1'
    'glibc-2.12-1.166.el6_7.3'
    'glibc-2.12-1.166.el6_7.7'
    'glibc-2.12-1.192.el6'
    'glibc-2.12-1.209.el6'
    'glibc-2.12-1.209.el6_9.1'
    'glibc-2.17-55.el7'
    'glibc-2.17-55.el7_0.1'
    'glibc-2.17-55.el7_0.3'
    'glibc-2.17-55.el7_0.5'
    'glibc-2.17-78.el7'
    'glibc-2.17-79.el7_1'
    'glibc-2.17-79.el7_1.4'
    'glibc-2.17-105.el7'
    'glibc-2.17-106.el7_2.1'
    'glibc-2.17-106.el7_2.4'
    'glibc-2.17-106.el7_2.6'
    'glibc-2.17-106.el7_2.8'
    'glibc-2.17-157.el7'
    'glibc-2.17-157.el7_3.1'
    'glibc-2.17-157.el7_3.1'
    'glibc-2.17-157.el7_3.2'
)

VULNERABLE_KERNELS=(
    '3.10.0-229.1.2.ael7b'
    '3.10.0-229.4.2.ael7b'
    '3.10.0-229.7.2.ael7b'
    '3.10.0-229.11.1.ael7b'
    '3.10.0-229.14.1.ael7b'
    '3.10.0-229.20.1.ael7b'
    '3.10.0-229.24.2.ael7b'
    '3.10.0-229.26.2.ael7b'
    '3.10.0-229.28.1.ael7b'
    '3.10.0-229.30.1.ael7b'
    '3.10.0-229.34.1.ael7b'
    '3.10.0-229.38.1.ael7b'
    '3.10.0-229.40.1.ael7b'
    '3.10.0-229.42.1.ael7b'
    '3.10.0-229.42.2.ael7b'
    '3.10.0-229.44.1.ael7b'
    '3.10.0-229.46.1.ael7b'
    '3.10.0-229.48.1.ael7b'
    '3.10.0-229.49.1.ael7b'
    '2.6.18-8.1.1.el5'
    '2.6.18-8.1.3.el5'
    '2.6.18-8.1.4.el5'
    '2.6.18-8.1.6.el5'
    '2.6.18-8.1.8.el5'
    '2.6.18-8.1.10.el5'
    '2.6.18-8.1.14.el5'
    '2.6.18-8.1.15.el5'
    '2.6.18-53.el5'
    '2.6.18-53.1.4.el5'
    '2.6.18-53.1.6.el5'
    '2.6.18-53.1.13.el5'
    '2.6.18-53.1.14.el5'
    '2.6.18-53.1.19.el5'
    '2.6.18-53.1.21.el5'
    '2.6.18-92.el5'
    '2.6.18-92.1.1.el5'
    '2.6.18-92.1.6.el5'
    '2.6.18-92.1.10.el5'
    '2.6.18-92.1.13.el5'
    '2.6.18-92.1.18.el5'
    '2.6.18-92.1.22.el5'
    '2.6.18-92.1.24.el5'
    '2.6.18-92.1.26.el5'
    '2.6.18-92.1.27.el5'
    '2.6.18-92.1.28.el5'
    '2.6.18-92.1.29.el5'
    '2.6.18-92.1.32.el5'
    '2.6.18-92.1.35.el5'
    '2.6.18-92.1.38.el5'
    '2.6.18-128.el5'
    '2.6.18-128.1.1.el5'
    '2.6.18-128.1.6.el5'
    '2.6.18-128.1.10.el5'
    '2.6.18-128.1.14.el5'
    '2.6.18-128.1.16.el5'
    '2.6.18-128.2.1.el5'
    '2.6.18-128.4.1.el5'
    '2.6.18-128.4.1.el5'
    '2.6.18-128.7.1.el5'
    '2.6.18-128.8.1.el5'
    '2.6.18-128.11.1.el5'
    '2.6.18-128.12.1.el5'
    '2.6.18-128.14.1.el5'
    '2.6.18-128.16.1.el5'
    '2.6.18-128.17.1.el5'
    '2.6.18-128.18.1.el5'
    '2.6.18-128.23.1.el5'
    '2.6.18-128.23.2.el5'
    '2.6.18-128.25.1.el5'
    '2.6.18-128.26.1.el5'
    '2.6.18-128.27.1.el5'
    '2.6.18-128.29.1.el5'
    '2.6.18-128.30.1.el5'
    '2.6.18-128.31.1.el5'
    '2.6.18-128.32.1.el5'
    '2.6.18-128.35.1.el5'
    '2.6.18-128.36.1.el5'
    '2.6.18-128.37.1.el5'
    '2.6.18-128.38.1.el5'
    '2.6.18-128.39.1.el5'
    '2.6.18-128.40.1.el5'
    '2.6.18-128.41.1.el5'
    '2.6.18-164.el5'
    '2.6.18-164.2.1.el5'
    '2.6.18-164.6.1.el5'
    '2.6.18-164.9.1.el5'
    '2.6.18-164.10.1.el5'
    '2.6.18-164.11.1.el5'
    '2.6.18-164.15.1.el5'
    '2.6.18-164.17.1.el5'
    '2.6.18-164.19.1.el5'
    '2.6.18-164.21.1.el5'
    '2.6.18-164.25.1.el5'
    '2.6.18-164.25.2.el5'
    '2.6.18-164.28.1.el5'
    '2.6.18-164.30.1.el5'
    '2.6.18-164.32.1.el5'
    '2.6.18-164.34.1.el5'
    '2.6.18-164.36.1.el5'
    '2.6.18-164.37.1.el5'
    '2.6.18-164.38.1.el5'
    '2.6.18-194.el5'
    '2.6.18-194.3.1.el5'
    '2.6.18-194.8.1.el5'
    '2.6.18-194.11.1.el5'
    '2.6.18-194.11.3.el5'
    '2.6.18-194.11.4.el5'
    '2.6.18-194.17.1.el5'
    '2.6.18-194.17.4.el5'
    '2.6.18-194.26.1.el5'
    '2.6.18-194.32.1.el5'
    '2.6.18-238.el5'
    '2.6.18-238.1.1.el5'
    '2.6.18-238.5.1.el5'
    '2.6.18-238.9.1.el5'
    '2.6.18-238.12.1.el5'
    '2.6.18-238.19.1.el5'
    '2.6.18-238.21.1.el5'
    '2.6.18-238.27.1.el5'
    '2.6.18-238.28.1.el5'
    '2.6.18-238.31.1.el5'
    '2.6.18-238.33.1.el5'
    '2.6.18-238.35.1.el5'
    '2.6.18-238.37.1.el5'
    '2.6.18-238.39.1.el5'
    '2.6.18-238.40.1.el5'
    '2.6.18-238.44.1.el5'
    '2.6.18-238.45.1.el5'
    '2.6.18-238.47.1.el5'
    '2.6.18-238.48.1.el5'
    '2.6.18-238.49.1.el5'
    '2.6.18-238.50.1.el5'
    '2.6.18-238.51.1.el5'
    '2.6.18-238.52.1.el5'
    '2.6.18-238.53.1.el5'
    '2.6.18-238.54.1.el5'
    '2.6.18-238.55.1.el5'
    '2.6.18-238.56.1.el5'
    '2.6.18-238.57.1.el5'
    '2.6.18-238.58.1.el5'
    '2.6.18-274.el5'
    '2.6.18-274.3.1.el5'
    '2.6.18-274.7.1.el5'
    '2.6.18-274.12.1.el5'
    '2.6.18-274.17.1.el5'
    '2.6.18-274.18.1.el5'
    '2.6.18-308.el5'
    '2.6.18-308.1.1.el5'
    '2.6.18-308.4.1.el5'
    '2.6.18-308.8.1.el5'
    '2.6.18-308.8.2.el5'
    '2.6.18-308.11.1.el5'
    '2.6.18-308.13.1.el5'
    '2.6.18-308.16.1.el5'
    '2.6.18-308.20.1.el5'
    '2.6.18-308.24.1.el5'
    '2.6.18-348.el5'
    '2.6.18-348.1.1.el5'
    '2.6.18-348.2.1.el5'
    '2.6.18-348.3.1.el5'
    '2.6.18-348.4.1.el5'
    '2.6.18-348.6.1.el5'
    '2.6.18-348.12.1.el5'
    '2.6.18-348.16.1.el5'
    '2.6.18-348.18.1.el5'
    '2.6.18-348.19.1.el5'
    '2.6.18-348.21.1.el5'
    '2.6.18-348.22.1.el5'
    '2.6.18-348.23.1.el5'
    '2.6.18-348.25.1.el5'
    '2.6.18-348.27.1.el5'
    '2.6.18-348.28.1.el5'
    '2.6.18-348.29.1.el5'
    '2.6.18-348.30.1.el5'
    '2.6.18-348.31.2.el5'
    '2.6.18-348.32.1.el5'
    '2.6.18-348.33.1.el5'
    '2.6.18-371.el5'
    '2.6.18-371.1.2.el5'
    '2.6.18-371.3.1.el5'
    '2.6.18-371.4.1.el5'
    '2.6.18-371.6.1.el5'
    '2.6.18-371.8.1.el5'
    '2.6.18-371.9.1.el5'
    '2.6.18-371.11.1.el5'
    '2.6.18-371.12.1.el5'
    '2.6.18-398.el5'
    '2.6.18-400.el5'
    '2.6.18-400.1.1.el5'
    '2.6.18-402.el5'
    '2.6.18-404.el5'
    '2.6.18-406.el5'
    '2.6.18-407.el5'
    '2.6.18-408.el5'
    '2.6.18-409.el5'
    '2.6.18-410.el5'
    '2.6.18-411.el5'
    '2.6.18-412.el5'
    '2.6.18-416.el5'
    '2.6.18-417.el5'
    '2.6.18-418.el5'
    '2.6.18-419.el5'
    '2.6.32-71.7.1.el6'
    '2.6.32-71.14.1.el6'
    '2.6.32-71.18.1.el6'
    '2.6.32-71.18.2.el6'
    '2.6.32-71.24.1.el6'
    '2.6.32-71.29.1.el6'
    '2.6.32-71.31.1.el6'
    '2.6.32-71.34.1.el6'
    '2.6.32-71.35.1.el6'
    '2.6.32-71.36.1.el6'
    '2.6.32-71.37.1.el6'
    '2.6.32-71.38.1.el6'
    '2.6.32-71.39.1.el6'
    '2.6.32-71.40.1.el6'
    '2.6.32-131.0.15.el6'
    '2.6.32-131.2.1.el6'
    '2.6.32-131.4.1.el6'
    '2.6.32-131.6.1.el6'
    '2.6.32-131.12.1.el6'
    '2.6.32-131.17.1.el6'
    '2.6.32-131.21.1.el6'
    '2.6.32-131.22.1.el6'
    '2.6.32-131.25.1.el6'
    '2.6.32-131.26.1.el6'
    '2.6.32-131.28.1.el6'
    '2.6.32-131.29.1.el6'
    '2.6.32-131.30.1.el6'
    '2.6.32-131.30.2.el6'
    '2.6.32-131.33.1.el6'
    '2.6.32-131.35.1.el6'
    '2.6.32-131.36.1.el6'
    '2.6.32-131.37.1.el6'
    '2.6.32-131.38.1.el6'
    '2.6.32-131.39.1.el6'
    '2.6.32-220.el6'
    '2.6.32-220.2.1.el6'
    '2.6.32-220.4.1.el6'
    '2.6.32-220.4.2.el6'
    '2.6.32-220.4.7.bgq.el6'
    '2.6.32-220.7.1.el6'
    '2.6.32-220.7.3.p7ih.el6'
    '2.6.32-220.7.4.p7ih.el6'
    '2.6.32-220.7.6.p7ih.el6'
    '2.6.32-220.7.7.p7ih.el6'
    '2.6.32-220.13.1.el6'
    '2.6.32-220.17.1.el6'
    '2.6.32-220.23.1.el6'
    '2.6.32-220.24.1.el6'
    '2.6.32-220.25.1.el6'
    '2.6.32-220.26.1.el6'
    '2.6.32-220.28.1.el6'
    '2.6.32-220.30.1.el6'
    '2.6.32-220.31.1.el6'
    '2.6.32-220.32.1.el6'
    '2.6.32-220.34.1.el6'
    '2.6.32-220.34.2.el6'
    '2.6.32-220.38.1.el6'
    '2.6.32-220.39.1.el6'
    '2.6.32-220.41.1.el6'
    '2.6.32-220.42.1.el6'
    '2.6.32-220.45.1.el6'
    '2.6.32-220.46.1.el6'
    '2.6.32-220.48.1.el6'
    '2.6.32-220.51.1.el6'
    '2.6.32-220.52.1.el6'
    '2.6.32-220.53.1.el6'
    '2.6.32-220.54.1.el6'
    '2.6.32-220.55.1.el6'
    '2.6.32-220.56.1.el6'
    '2.6.32-220.57.1.el6'
    '2.6.32-220.58.1.el6'
    '2.6.32-220.60.2.el6'
    '2.6.32-220.62.1.el6'
    '2.6.32-220.63.2.el6'
    '2.6.32-220.64.1.el6'
    '2.6.32-220.65.1.el6'
    '2.6.32-220.66.1.el6'
    '2.6.32-220.67.1.el6'
    '2.6.32-220.68.1.el6'
    '2.6.32-220.69.1.el6'
    '2.6.32-220.70.1.el6'
    '2.6.32-220.71.1.el6'
    '2.6.32-279.el6'
    '2.6.32-279.1.1.el6'
    '2.6.32-279.2.1.el6'
    '2.6.32-279.5.1.el6'
    '2.6.32-279.5.2.el6'
    '2.6.32-279.9.1.el6'
    '2.6.32-279.11.1.el6'
    '2.6.32-279.14.1.bgq.el6'
    '2.6.32-279.14.1.el6'
    '2.6.32-279.19.1.el6'
    '2.6.32-279.22.1.el6'
    '2.6.32-279.23.1.el6'
    '2.6.32-279.25.1.el6'
    '2.6.32-279.25.2.el6'
    '2.6.32-279.31.1.el6'
    '2.6.32-279.33.1.el6'
    '2.6.32-279.34.1.el6'
    '2.6.32-279.37.2.el6'
    '2.6.32-279.39.1.el6'
    '2.6.32-279.41.1.el6'
    '2.6.32-279.42.1.el6'
    '2.6.32-279.43.1.el6'
    '2.6.32-279.43.2.el6'
    '2.6.32-279.46.1.el6'
    '2.6.32-358.el6'
    '2.6.32-358.0.1.el6'
    '2.6.32-358.2.1.el6'
    '2.6.32-358.6.1.el6'
    '2.6.32-358.6.2.el6'
    '2.6.32-358.6.3.p7ih.el6'
    '2.6.32-358.11.1.bgq.el6'
    '2.6.32-358.11.1.el6'
    '2.6.32-358.14.1.el6'
    '2.6.32-358.18.1.el6'
    '2.6.32-358.23.2.el6'
    '2.6.32-358.28.1.el6'
    '2.6.32-358.32.3.el6'
    '2.6.32-358.37.1.el6'
    '2.6.32-358.41.1.el6'
    '2.6.32-358.44.1.el6'
    '2.6.32-358.46.1.el6'
    '2.6.32-358.46.2.el6'
    '2.6.32-358.48.1.el6'
    '2.6.32-358.49.1.el6'
    '2.6.32-358.51.1.el6'
    '2.6.32-358.51.2.el6'
    '2.6.32-358.55.1.el6'
    '2.6.32-358.56.1.el6'
    '2.6.32-358.59.1.el6'
    '2.6.32-358.61.1.el6'
    '2.6.32-358.62.1.el6'
    '2.6.32-358.65.1.el6'
    '2.6.32-358.67.1.el6'
    '2.6.32-358.68.1.el6'
    '2.6.32-358.69.1.el6'
    '2.6.32-358.70.1.el6'
    '2.6.32-358.71.1.el6'
    '2.6.32-358.72.1.el6'
    '2.6.32-358.73.1.el6'
    '2.6.32-358.75.1.el6'
    '2.6.32-358.76.1.el6'
    '2.6.32-358.77.1.el6'
    '2.6.32-358.78.1.el6'
    '2.6.32-358.79.1.el6'
    '2.6.32-358.111.1.openstack.el6'
    '2.6.32-358.114.1.openstack.el6'
    '2.6.32-358.118.1.openstack.el6'
    '2.6.32-358.123.4.openstack.el6'
    '2.6.32-431.el6'
    '2.6.32-431.1.1.bgq.el6'
    '2.6.32-431.1.2.el6'
    '2.6.32-431.3.1.el6'
    '2.6.32-431.5.1.el6'
    '2.6.32-431.11.2.el6'
    '2.6.32-431.17.1.el6'
    '2.6.32-431.20.3.el6'
    '2.6.32-431.20.5.el6'
    '2.6.32-431.23.3.el6'
    '2.6.32-431.29.2.el6'
    '2.6.32-431.37.1.el6'
    '2.6.32-431.40.1.el6'
    '2.6.32-431.40.2.el6'
    '2.6.32-431.46.2.el6'
    '2.6.32-431.50.1.el6'
    '2.6.32-431.53.2.el6'
    '2.6.32-431.56.1.el6'
    '2.6.32-431.59.1.el6'
    '2.6.32-431.61.2.el6'
    '2.6.32-431.64.1.el6'
    '2.6.32-431.66.1.el6'
    '2.6.32-431.68.1.el6'
    '2.6.32-431.69.1.el6'
    '2.6.32-431.70.1.el6'
    '2.6.32-431.71.1.el6'
    '2.6.32-431.72.1.el6'
    '2.6.32-431.73.2.el6'
    '2.6.32-431.74.1.el6'
    '2.6.32-431.75.1.el6'
    '2.6.32-431.75.1.el6'
    '2.6.32-431.76.1.el6'
    '2.6.32-431.77.1.el6'
    '2.6.32-431.77.1.el6'
    '2.6.32-431.78.1.el6'
    '2.6.32-431.78.1.el6'
    '2.6.32-431.79.1.el6'
    '2.6.32-431.79.1.el6'
    '2.6.32-431.80.1.el6'
    '2.6.32-431.80.1.el6'
    '2.6.32-504.el6'
    '2.6.32-504.1.3.el6'
    '2.6.32-504.3.3.el6'
    '2.6.32-504.8.1.el6'
    '2.6.32-504.8.2.bgq.el6'
    '2.6.32-504.12.2.el6'
    '2.6.32-504.16.2.el6'
    '2.6.32-504.23.4.el6'
    '2.6.32-504.30.3.el6'
    '2.6.32-504.30.5.p7ih.el6'
    '2.6.32-504.30.6.p7ih.el6'
    '2.6.32-504.33.2.el6'
    '2.6.32-504.36.1.el6'
    '2.6.32-504.38.1.el6'
    '2.6.32-504.40.1.el6'
    '2.6.32-504.43.1.el6'
    '2.6.32-504.46.1.el6'
    '2.6.32-504.49.1.el6'
    '2.6.32-504.50.1.el6'
    '2.6.32-504.51.1.el6'
    '2.6.32-504.52.1.el6'
    '2.6.32-504.54.1.el6'
    '2.6.32-504.55.1.el6'
    '2.6.32-504.56.1.el6'
    '2.6.32-504.56.1.el6'
    '2.6.32-504.57.1.el6'
    '2.6.32-504.57.1.el6'
    '2.6.32-504.58.1.el6'
    '2.6.32-504.58.1.el6'
    '2.6.32-573.el6'
    '2.6.32-573.1.1.el6'
    '2.6.32-573.3.1.el6'
    '2.6.32-573.4.2.bgq.el6'
    '2.6.32-573.7.1.el6'
    '2.6.32-573.8.1.el6'
    '2.6.32-573.12.1.el6'
    '2.6.32-573.18.1.el6'
    '2.6.32-573.22.1.el6'
    '2.6.32-573.26.1.el6'
    '2.6.32-573.30.1.el6'
    '2.6.32-573.32.1.el6'
    '2.6.32-573.34.1.el6'
    '2.6.32-573.35.1.el6'
    '2.6.32-573.35.2.el6'
    '2.6.32-573.37.1.el6'
    '2.6.32-573.38.1.el6'
    '2.6.32-573.40.1.el6'
    '2.6.32-573.41.1.el6'
    '2.6.32-573.42.1.el6'
    '2.6.32-642.el6'
    '2.6.32-642.1.1.el6'
    '2.6.32-642.3.1.el6'
    '2.6.32-642.4.2.el6'
    '2.6.32-642.6.1.el6'
    '2.6.32-642.6.2.el6'
    '2.6.32-642.11.1.el6'
    '2.6.32-642.13.1.el6'
    '2.6.32-642.13.2.el6'
    '2.6.32-642.15.1.el6'
    '2.6.32-696.el6'
    '2.6.32-696.1.1.el6'
    '2.6.32-696.3.1.el6'
    '3.10.0-123.el7'
    '3.10.0-123.1.2.el7'
    '3.10.0-123.4.2.el7'
    '3.10.0-123.4.4.el7'
    '3.10.0-123.6.3.el7'
    '3.10.0-123.8.1.el7'
    '3.10.0-123.9.2.el7'
    '3.10.0-123.9.3.el7'
    '3.10.0-123.13.1.el7'
    '3.10.0-123.13.2.el7'
    '3.10.0-123.20.1.el7'
    '3.10.0-229.el7'
    '3.10.0-229.1.2.el7'
    '3.10.0-229.4.2.el7'
    '3.10.0-229.7.2.el7'
    '3.10.0-229.11.1.el7'
    '3.10.0-229.14.1.el7'
    '3.10.0-229.20.1.el7'
    '3.10.0-229.24.2.el7'
    '3.10.0-229.26.2.el7'
    '3.10.0-229.28.1.el7'
    '3.10.0-229.30.1.el7'
    '3.10.0-229.34.1.el7'
    '3.10.0-229.38.1.el7'
    '3.10.0-229.40.1.el7'
    '3.10.0-229.42.1.el7'
    '3.10.0-229.42.2.el7'
    '3.10.0-229.44.1.el7'
    '3.10.0-229.46.1.el7'
    '3.10.0-229.48.1.el7'
    '3.10.0-229.49.1.el7'
    '3.10.0-327.el7'
    '3.10.0-327.3.1.el7'
    '3.10.0-327.4.4.el7'
    '3.10.0-327.4.5.el7'
    '3.10.0-327.10.1.el7'
    '3.10.0-327.13.1.el7'
    '3.10.0-327.18.2.el7'
    '3.10.0-327.22.2.el7'
    '3.10.0-327.28.2.el7'
    '3.10.0-327.28.3.el7'
    '3.10.0-327.36.1.el7'
    '3.10.0-327.36.2.el7'
    '3.10.0-327.36.3.el7'
    '3.10.0-327.41.3.el7'
    '3.10.0-327.41.4.el7'
    '3.10.0-327.44.2.el7'
    '3.10.0-327.46.1.el7'
    '3.10.0-327.49.2.el7'
    '3.10.0-327.53.1.el7'
    '3.10.0-327.55.1.el7'
    '3.10.0-514.el7'
    '3.10.0-514.2.2.el7'
    '3.10.0-514.6.1.el7'
    '3.10.0-514.6.2.el7'
    '3.10.0-514.10.2.el7'
    '3.10.0-514.16.1.el7'
    '3.10.0-514.16.2.p7ih.el7'
    '3.10.0-514.21.1.el7'
    '2.6.24.7-74.el5rt'
    '2.6.24.7-81.el5rt'
    '2.6.24.7-93.el5rt'
    '2.6.24.7-101.el5rt'
    '2.6.24.7-108.el5rt'
    '2.6.24.7-111.el5rt'
    '2.6.24.7-117.el5rt'
    '2.6.24.7-126.el5rt'
    '2.6.24.7-132.el5rt'
    '2.6.24.7-137.el5rt'
    '2.6.24.7-139.el5rt'
    '2.6.24.7-146.el5rt'
    '2.6.24.7-149.el5rt'
    '2.6.24.7-161.el5rt'
    '2.6.24.7-169.el5rt'
    '2.6.33.7-rt29.45.el5rt'
    '2.6.33.7-rt29.47.el5rt'
    '2.6.33.7-rt29.55.el5rt'
    '2.6.33.9-rt31.64.el5rt'
    '2.6.33.9-rt31.67.el5rt'
    '2.6.33.9-rt31.86.el5rt'
    '2.6.33.9-rt31.66.el6rt'
    '2.6.33.9-rt31.74.el6rt'
    '2.6.33.9-rt31.75.el6rt'
    '2.6.33.9-rt31.79.el6rt'
    '3.0.9-rt26.45.el6rt'
    '3.0.9-rt26.46.el6rt'
    '3.0.18-rt34.53.el6rt'
    '3.0.25-rt44.57.el6rt'
    '3.0.30-rt50.62.el6rt'
    '3.0.36-rt57.66.el6rt'
    '3.2.23-rt37.56.el6rt'
    '3.2.33-rt50.66.el6rt'
    '3.6.11-rt28.20.el6rt'
    '3.6.11-rt30.25.el6rt'
    '3.6.11.2-rt33.39.el6rt'
    '3.6.11.5-rt37.55.el6rt'
    '3.8.13-rt14.20.el6rt'
    '3.8.13-rt14.25.el6rt'
    '3.8.13-rt27.33.el6rt'
    '3.8.13-rt27.34.el6rt'
    '3.8.13-rt27.40.el6rt'
    '3.10.0-229.rt56.144.el6rt'
    '3.10.0-229.rt56.147.el6rt'
    '3.10.0-229.rt56.149.el6rt'
    '3.10.0-229.rt56.151.el6rt'
    '3.10.0-229.rt56.153.el6rt'
    '3.10.0-229.rt56.158.el6rt'
    '3.10.0-229.rt56.161.el6rt'
    '3.10.0-229.rt56.162.el6rt'
    '3.10.0-327.rt56.170.el6rt'
    '3.10.0-327.rt56.171.el6rt'
    '3.10.0-327.rt56.176.el6rt'
    '3.10.0-327.rt56.183.el6rt'
    '3.10.0-327.rt56.190.el6rt'
    '3.10.0-327.rt56.194.el6rt'
    '3.10.0-327.rt56.195.el6rt'
    '3.10.0-327.rt56.197.el6rt'
    '3.10.0-327.rt56.198.el6rt'
    '3.10.0-327.rt56.199.el6rt'
    '3.10.0-514.rt56.210.el6rt'
    '3.10.0-514.rt56.215.el6rt'
    '3.10.0-514.rt56.219.el6rt'
    '3.10.0-514.rt56.221.el6rt'
    '3.10.33-rt32.33.el6rt'
    '3.10.33-rt32.34.el6rt'
    '3.10.33-rt32.43.el6rt'
    '3.10.33-rt32.45.el6rt'
    '3.10.33-rt32.51.el6rt'
    '3.10.33-rt32.52.el6rt'
    '3.10.58-rt62.58.el6rt'
    '3.10.58-rt62.60.el6rt'
    '3.10.0-229.rt56.141.el7'
    '3.10.0-229.1.2.rt56.141.2.el7_1'
    '3.10.0-229.4.2.rt56.141.6.el7_1'
    '3.10.0-229.7.2.rt56.141.6.el7_1'
    '3.10.0-229.11.1.rt56.141.11.el7_1'
    '3.10.0-229.14.1.rt56.141.13.el7_1'
    '3.10.0-229.20.1.rt56.141.14.el7_1'
    '3.10.0-327.rt56.204.el7'
    '3.10.0-327.4.5.rt56.206.el7_2'
    '3.10.0-327.10.1.rt56.211.el7_2'
    '3.10.0-327.13.1.rt56.216.el7_2'
    '3.10.0-327.18.2.rt56.223.el7_2'
    '3.10.0-327.22.2.rt56.230.el7_2'
    '3.10.0-327.28.2.rt56.234.el7_2'
    '3.10.0-327.28.3.rt56.235.el7'
    '3.10.0-327.36.1.rt56.237.el7'
    '3.10.0-327.36.3.rt56.238.el7'
    '3.10.0-514.rt56.420.el7'
    '3.10.0-514.2.2.rt56.424.el7'
    '3.10.0-514.6.1.rt56.429.el7'
    '3.10.0-514.6.1.rt56.430.el7'
    '3.10.0-514.10.2.rt56.435.el7'
    '3.10.0-514.16.1.rt56.437.el7'
    '3.10.0-514.21.1.rt56.438.el7'
)

KPATCH_MODULE_NAMES=(
    'kpatch_3_10_0_514_21_1_1_2'
    'kpatch_3_10_0_327_36_3_1_2'
)


basic_args() {
    # Parses basic commandline arguments and sets basic environment.
    #
    # Args:
    #     parameters - an array of commandline arguments
    #
    # Side effects:
    #     Exits if --help parameters is used
    #     Sets COLOR constants and debug variable

    parameters=( "$@" )

    RED="\033[1;31m"
    YELLOW="\033[1;33m"
    GREEN="\033[1;32m"
    BOLD="\033[1m"
    RESET="\033[0m"
    for parameter in "${parameters[@]}"; do
        if [[ "$parameter" == "-h" || "$parameter" == "--help" ]]; then
            echo "Usage: $( basename "$0" ) [-n | --no-colors] [-d | --debug]"
            # exit 1
            return 1
        elif [[ "$parameter" == "-n" || "$parameter" == "--no-colors" ]]; then
            RED=""
            YELLOW=""
            GREEN=""
            BOLD=""
            RESET=""
        elif [[ "$parameter" == "-d" || "$parameter" == "--debug" ]]; then
            debug=true
        fi
    done
}


basic_reqs() {
    # Prints common disclaimer and checks basic requirements.
    #
    # Args:
    #     CVE - string printed in the disclaimer
    #
    # Side effects:
    #     Exits when 'rpm' command is not available

    CVE="$1"

    # Disclaimer
    echo
    echo -e "${BOLD}This script is primarily designed to detect $CVE on supported"
    echo -e "Red Hat Enterprise Linux systems and kernel packages."
    echo -e "Result may be inaccurate for other RPM based systems.${RESET}"
    echo

    # RPM is required
    if ! command -v rpm &> /dev/null; then
        echo "'rpm' command is required, but not installed. Exiting."
        # exit 1
        return 1
    fi
}


check_supported_kernel() {
    # Checks if running kernel is supported.
    #
    # Args:
    #     running_kernel - kernel string as returned by 'uname -r'
    #
    # Side effects:
    #     Exits when running kernel is obviously not supported

    running_kernel="$1"

    # Check supported platform
    if [[ "$running_kernel" != *".el"[5-7]* ]]; then
        echo -e "${RED}This script is meant to be used only on Red Hat Enterprise"
        echo -e "Linux 5, 6 and 7.${RESET}"
        # exit 1
        return 1
    fi
}


check_kernel() {
    # Checks kernel if it is in list of vulnerable kernels.
    #
    # Args:
    #     running_kernel - kernel string as returned by 'uname -r'
    #     vulnerable_versions - an array of vulnerable versions
    #
    # Prints:
    #     Vulnerable kernel string as returned by 'uname -r', or nothing

    running_kernel="$1"
    shift
    vulnerable_versions=( "$@" )

    for tested_kernel in "${vulnerable_versions[@]}"; do
        if [[ "$running_kernel" == *"$tested_kernel"* ]]; then
            echo "$running_kernel"
            break
        fi
    done
}


check_kpatch() {
    # Checks if specific kpatch listed in a kpatch list is applied.
    #
    # Args:
    #     kpatch_module_names - an array of kpatches
    #
    # Prints:
    #     Found kpatch, or nothing

    kpatch_module_names=( "$@" )

    # Check lsmod availability
    if ! command -v lsmod &> /dev/null; then
        return
    fi

    # Get loaded kernel modules
    modules=$( lsmod )

    # Check if kpatch is installed
    for tested_kpatch in "${kpatch_module_names[@]}"; do
        if [[ "$modules" == *"$tested_kpatch"* ]]; then
            echo "$tested_kpatch"
            break
        fi
    done
}


check_package() {
    # Checks if installed package is in list of vulnerable packages.
    #
    # Args:
    #     installed_packages - installed packages string as returned by 'rpm -qa package'
    #                          (may be multiline)
    #     vulnerable_versions - an array of vulnerable versions
    #
    # Prints:
    #     First vulnerable package string as returned by 'rpm -qa package', or nothing

    installed_packages=( $1 )  # Convert to array, use word splitting
    shift
    vulnerable_versions=( "$@" )

    for tested_package in "${vulnerable_versions[@]}"; do
        for installed_package in "${installed_packages[@]}"; do
            installed_package_without_arch="${installed_package%.*}"
            if [[ "$installed_package_without_arch" == "$tested_package" ]]; then
                echo "$installed_package"
                return 0
            fi
        done
    done
}


get_installed_packages() {
    # Checks for installed packages of a 'package_name'. Compatible with RHEL5.
    #
    # Args:
    #     package_name - package name string
    #
    # Prints:
    #     Lines with N-V-R.A strings of all installed packages.

    package_name="$1"

    rpm -qa --queryformat="%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n" "$package_name"
}


if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    basic_args "$@"
    basic_reqs "CVE-1000366"
    running_kernel=$( uname -r )
    check_supported_kernel "$running_kernel"

    # Get installed glibc packages
    installed_packages=$( get_installed_packages "glibc" )

    # Basic checks
    vulnerable_package=$( check_package "$installed_packages" "${VULNERABLE_VERSIONS[@]}" )

    # Kernel checks
    vulnerable_kernel=$( check_kernel "$running_kernel" "${VULNERABLE_KERNELS[@]}" )
    applied_kpatch=$( check_kpatch "${KPATCH_MODULE_NAMES[@]}" )

    if [[ "$vulnerable_kernel" && ! "$applied_kpatch" ]]; then
        kernel_exploitable="true"
    fi

    # Debug prints
    if [[ "$debug" ]]; then
        echo "running_kernel = *$running_kernel*"
        echo "vulnerable_kernel = *$vulnerable_kernel*"
        echo "applied_kpatch = *$applied_kpatch*"
        echo "installed_packages = *$installed_packages*"
        echo "vulnerable_package = *$vulnerable_package*"
        echo "kernel_exploitable = *$kernel_exploitable*"
        echo
    fi

    # Results
    echo -e "Detected 'glibc' packages are:${BOLD}"
    echo -e "$installed_packages${RESET}"
    echo -e "Detected running kernel is '${BOLD}$running_kernel${RESET}'."
    echo

    if [[ "$vulnerable_package" ]]; then
        echo -e "${RED}This 'glibc' version is vulnerable.${RESET}"
        echo -e "Update 'glibc' package and ${YELLOW}restart the system${RESET}."
        echo -e "Follow https://access.redhat.com/security/vulnerabilities/stackguard for advice."
    else
        echo -e "${GREEN}This 'glibc' version is not vulnerable.${RESET}"
    fi

    if [[ "$vulnerable_kernel" ]]; then
        if [[ "$applied_kpatch" ]]; then
            echo -e "${YELLOW}This 'kernel' version is vulnerable.${RESET}"
            echo -e "${GREEN}You have correct kpatch installed${RESET} and the kernel vulnerability"
            echo -e "is not exploitable."
        else
            echo -e "${RED}This 'kernel' version is vulnerable.${RESET}"
            echo -e "Update 'kernel' package and ${YELLOW}restart the system${RESET}."
            echo -e "Follow https://access.redhat.com/security/vulnerabilities/stackguard for advice."
        fi
    else
        echo -e "${GREEN}This 'kernel' version is not vulnerable.${RESET}"
    fi

    if [[ "$kernel_exploitable" && "$vulnerable_package" ]]; then
        # exit 2  # Both exploitable
        return 2  # Both exploitable
    elif [[ "$kernel_exploitable" ]]; then
        # exit 3  # Only kernel exploitable
        return 3  # Only kernel exploitable
    elif [[ "$vulnerable_package" ]]; then
        # exit 4  # Only glibc exploitable
        return 4  # Only glibc exploitable
    else
        # exit 0
        return 0
    fi
fi
}

cmd="GHOST_test"
targetFile="ghost.txt"
save_file

cmd="shellshock_test"
targetFile="bash.txt"
save_file
 
cmd="cve_2017_1000366_2"
targetFile="kernel.txt"
save_file
 
## 信息收集完成并打包
cd ${dataDir}
local_file="${ip_addr}.tar.gz"

echo "..."
echo

tar -czf ${local_file} ${ip_addr}

echo "File \"${local_file}\" generated!"
echo "+--------------------------------+"
echo '| Data collected successfully!!! |'
echo "+--------------------------------+"
echo
