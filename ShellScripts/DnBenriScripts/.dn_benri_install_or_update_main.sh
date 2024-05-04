#!/bin/bash

set -eu

export DEBIAN_FRONTEND=noninteractive

### ============= bash スクリプト =============

cat <<\EOF > /etc/profile.d/dn_benri_aliases.sh
# by dnobori

# テスト
alias dn_test1='echo Test1 OK!'

# 便利関数の更新
alias dn_update_benri='bash -c "bash <( curl --raw https://raw.githubusercontent.com/IPA-CyberLab/IPA-DN-Misc/main/ShellScripts/DnBenriScripts/install.sh )" ; source /etc/profile.d/dn_benri_aliases.sh'

# プロセス関係
function dn_process_getexe() {
    command readlink -f /proc/$1/exe
}

function dn_process_findexe() {
    ps ww -H -eo pid | awk '{print $1;}' | sort -n | uniq | xargs -n 1 -P 1 -IXXX readlink -f /proc/XXX/exe | grep -F -i $1 | sort | uniq
}


# システム関係
alias dn_danger_reboot='echo Rebooting forcefully. Syncing... ; sync ; sync ; sync ; echo Sync OK. Rebooting... ; sleep 0.5 ; /sbin/reboot --force'
alias dn_danger_rebootbios='echo Rebooting forcefully 2. Syncing... ; sync ; sync ; sync ; echo Sync OK. Rebooting with BIOS... ; sleep 0.5 ; echo 1 > /proc/sys/kernel/sysrq ; echo b > /proc/sysrq-trigger ; echo Perhaps triggered'

function dn_dir_sort_size() {
  command du -x -h -d 1 $@ | sort -h
}



# ネットワーク関係
alias dn_tcpdump_vlan='tcpdump -e -n -nn -v -i'

# LXD 関係
alias dn_lxc_show_vm='lxc list -c nsN46lc,boot.autostart:boot,volatile.last_state.power:last'
function dn_lxc_autoboot_enable()
{
  command lxc config set $1 boot.autostart true
}
function dn_lxc_autoboot_disable()
{
  command lxc config set $1 boot.autostart false
}
function dn_lxc_autoboot_unset()
{
  command lxc config unset $1 boot.autostart
}

alias dn_ping='ping -O -i 0.3'
alias pingg='ping -O -i 0.3'
alias pin='ping -O -i 0.3'


# システムユーティリティ関係
alias dff='df --human-readable --print-type --exclude-type=tmpfs --exclude-type=efivarfs --exclude-type=squashfs --exclude-type=devtmpfs'

alias getip='(echo -n "Hostname: " ; (hostname | sed -z "s/[\n\r]//g" ; echo " "; hostname --all-fqdns) | xargs) ; echo; ip -br link show ; echo ; ip -br address show | grep --color=never -E "^[0-9a-zA-Z\~\!\#\&\*\(\)\+\=\;\<\>\,\-\_\@\/\.\:\%]+ +[0-9a-zA-Z\~\!\#\&\*\(\)\+\=\;\<\>\,\-\_\@\/\.\:\%]+ +[0-9a-zA-Z\~\!\#\&\*\(\)\+\=\;\<\>\,\-\_\@\/\.\:\%]+.*$" ; echo ; (curl --silent --fail --connect-timeout 1.0 --noproxy "*" "http://getmyip-v4.arpanet.jp/?fqdn=1&port=1&all=1" | xargs) ; (curl --silent --fail --connect-timeout 1.0 --noproxy "*" "http://getmyip-v6.arpanet.jp/?fqdn=1&port=1&all=1" | xargs)'

alias sysinfo='/bin/se_generate_login_banner'
alias getinfo='/bin/se_generate_login_banner'
alias state='/bin/se_generate_login_banner'
alias status='/bin/se_generate_login_banner'
alias ver='/bin/se_generate_login_banner'
alias version='/bin/se_generate_login_banner'




# git 関係
alias dn_git_update='(cd $(git rev-parse --show-toplevel) && git pull && git submodule update --init --recursive)'


# Docker 関係
alias dn_docker_show_containers='docker ps -a'
alias dn_docker_show_containers_size='docker ps -a -s'
alias dn_docker_show_containers_running='docker ps'
alias dn_docker_show_containers_running_size='docker ps -s'
alias dn_docker_show_containers_size_running='docker ps -s'
alias dn_docker_show_running_containers='docker ps'
alias dn_docker_show_running_containers_size='docker ps -s'
alias dn_docker_show_images='docker image ls'



alias dn_docker_show_volumes='docker volume ls'

alias dn_docker_show_volumes_size='docker system df -v'

alias dn_docker_show_volumes_used_by='python3 -c "
import os
import subprocess
storages = []
flag = False
docker_result = subprocess.run(\"docker system df -v\", shell=True, stdout=subprocess.PIPE, encoding=\"utf-8\")
if True:
    lines = docker_result.stdout.splitlines()
    for line in lines:
        tokens = line.split()
        if ((tokens[0] if tokens[0:] else \"\") == \"VOLUME\" and (tokens[1] if tokens[1:] else \"\") == \"NAME\"):
            flag=True
        else:
            if len(tokens) == 0:
                flag=False
            else:
                if flag:
                    storage={\"name\":tokens[0],\"links\":int(tokens[1]),\"size\":tokens[2]}
                    storages.append(storage)
storages.sort(key=lambda x:format((100000000 - x[\"links\"]), \"09\") + \"_\" + x[\"name\"])
num = 0
for storage in storages:
    print(f\"## Storage {num}: {storage['"'"'name'"'"']} (links: {storage['"'"'links'"'"']}) [size: {storage['"'"'size'"'"']}]\")
    os.system(f\"docker ps -a --filter volume={storage['"'"'name'"'"']}\")
    print(\"\")
    num += 1
"'

alias dn_docker_run='docker run -it --rm'
alias dn_docker_exec='docker exec -it'
function dn_docker_exec_bash()
{
  command docker exec -it $1 /bin/bash
}





alias dn_copy_if_diff='python3 -c "
import os
import json
import subprocess
import inspect
import sys
import time as systime
import argparse
import shutil

def IsSameFile(a: str, b: str):
    if not os.path.exists(a):
        return False

    if not os.path.exists(b):
        return False

    with open(a, mode='"'"'rb'"'"') as f:
        src_data = f.read()
    
    with open(b, mode='"'"'rb'"'"') as f:
        dst_data = f.read()
    
    if len(src_data) != len(dst_data):
        return False
    
    return src_data == dst_data

if __name__ == '"'"'__main__'"'"':
    parser = argparse.ArgumentParser()
    parser.add_argument(\"src\", metavar=\"<src>\", type=str, help=\"Source filename\")
    parser.add_argument(\"-d\", dest=\"dst\", required=True,
                        type=str, help=\"Destination filename\")

    args = parser.parse_args()
    src = args.src
    dst = args.dst

    try:
        isSame = IsSameFile(src, dst)
    except:
        isSame = False

    if not isSame:
        shutil.copyfile(src, dst)

"'







alias dn_replace_str='python3 -c "
import os
import json
import subprocess
import inspect
import typing
import sys
import time as systime
import argparse
from typing import List, Tuple, Dict, Set, Callable, TypeVar, Type
from datetime import timedelta, tzinfo, timezone, time, date, datetime
    
def HasFileBom(filename):
    with open(filename, \"r\", encoding=\"utf-8\") as f:
        first_line = f.readline()
        return (first_line[0] == \"\ufeff\")

def IsNullOrZeroLen(str: str) -> bool:
    if StrIsNull(str) or len(str) == 0:
        return True
    return False

def ReplaceStr(str: str, oldKeyword: str, newKeyword: str, caseSensitive: bool = False) -> str:
    str = NonNullStr(str)
    if IsNullOrZeroLen(str):
        return \"\"
    oldKeyword = NonNullStr(oldKeyword)
    newKeyword = NonNullStr(newKeyword)
    if IsNullOrZeroLen(oldKeyword):
        return str

    i = 0
    j = 0
    num = 0
    sb = \"\"

    len_string = len(str)
    len_old = len(oldKeyword)
    len_new = len(newKeyword)

    while True:
        i = SearchStr(str, oldKeyword, i, caseSensitive)
        if i == -1:
            sb += str[j:]
            break
        num += 1
        sb += str[j:i]
        sb += newKeyword

        i += len_old
        j = i

    return sb

def SearchStr(str: str, keyword: str, start: int = 0, caseSensitive: bool = False) -> int:
    str = NonNullStr(str)
    keyword = NonNullStr(keyword)
    if IsNullOrZeroLen(str) or IsNullOrZeroLen(keyword):
        return -1
    if not caseSensitive:
        str = str.lower()
        keyword = keyword.lower()
    return str.find(keyword, start)


def ObjIsNull(object: any) -> bool:
    if object is None:
        return True
    return False

def StrIsNull(str: str) -> bool:
    return ObjIsNull(str)
    
def NonNullStr(str: str) -> str:
    if StrIsNull(str):
        return \"\"
    return str

def StrTrim(str: str) -> str:
    return NonNullStr(str).strip()

def StrLen(str: str) -> int:
    if StrIsNull(str):
        return 0
    return len(str)

def IsSamei(s1: str, s2: str) -> bool:
    return StrCmpi(s1, s2)

def StrCmpi(s1: str, s2: str) -> bool:
    s1 = NonNullStr(s1).lower()
    s2 = NonNullStr(s2).lower()
    return s1 == s2

def IsSame(s1: str, s2: str) -> bool:
    return StrCmp(s1, s2)

def StrCmp(s1: str, s2: str) -> bool:
    s1 = NonNullStr(s1)
    s2 = NonNullStr(s2)
    return s1 == s2

def IsEmptyStr(str: str) -> bool:
    if StrLen(StrTrim(str)) == 0:
        return True
    return False

def IsFilledStr(str: str) -> bool:
    return not IsEmptyStr(str)

def GetLines(src: str, removeEmpty: bool = False, trim: bool = False) -> List[str]:
    ret = list()
    for line in NonNullStr(src).splitlines():
        if trim:
            line = StrTrim(line)

        if not removeEmpty or IsFilledStr(line):
            ret.append(line)
    return ret

if __name__ == '"'"'__main__'"'"':
    parser = argparse.ArgumentParser()
    parser.add_argument(\"src\", metavar=\"<src>\", type=str, help=\"Source filename\")
    parser.add_argument(\"-d\", dest=\"dst\",
                        type=str, help=\"Destination filename\")
    parser.add_argument(\"-i\", dest=\"ignoreCase\", action=\"store_true\",
                        help=\"Ignore cases\")
    parser.add_argument(\"-p\", dest=\"partialMode\", action=\"store_true\",
                        help=\"Allow partial replacement in a line\")
    parser.add_argument(\"-t\", dest=\"trimMode\", action=\"store_true\",
                        help=\"Trim whitespaces\")
    parser.add_argument(\"-a\", dest=\"strA\",
                        type=str, help=\"Search string (old string)\")
    parser.add_argument(\"-b\", dest=\"strB\",
                        type=str, help=\"Replace string (new string)\")
    args = parser.parse_args()
    src = args.src
    dst = args.dst
    ignoreCase = args.ignoreCase
    partialMode = args.partialMode
    trimMode = args.trimMode

    searchStr = args.strA
    replaceStr = args.strB

    if IsNullOrZeroLen(searchStr):
        body = sys.stdin.read()
        stdinLines = GetLines(body)
        if len(stdinLines) < 2:
            raise \"You didn'"'"'t specified the -a option string. You must specify two lines (first line: old string, second line: new string) from stdin.\"
        searchStr = stdinLines[0]
        replaceStr = stdinLines[1]

    if trimMode:
        searchStr = StrTrim(searchStr)

    if IsNullOrZeroLen(searchStr):
        raise \"Search target string is empty.\"

    if IsEmptyStr(dst):
        dst = src
    
    hasBom = HasFileBom(src)
    
    with open(src, \"rt\", encoding=\"utf_8_sig\") as f:
        body = f.read()
        srcLines = GetLines(body)
    
    dstLines = list()

    numReplaced = 0

    for line in srcLines:
        if ignoreCase == False:
            if partialMode == False:
                tmp = line
                if trimMode:
                    tmp = StrTrim(tmp)
                if StrCmp(tmp, searchStr):
                    line = replaceStr
                    numReplaced += 1
            else:
                if SearchStr(line, searchStr, 0, True) != -1:
                    line = ReplaceStr(line, searchStr, replaceStr, True)
                    numReplaced += 1
        else:
            if partialMode == False:
                tmp = line
                if trimMode:
                    tmp = StrTrim(tmp)
                if StrCmpi(tmp, searchStr):
                    line = replaceStr
                    numReplaced += 1
            else:
                if SearchStr(line, searchStr, 0, False) != -1:
                    line = ReplaceStr(line, searchStr, replaceStr, False)
                    numReplaced += 1
        
        dstLines.append(line)

    saveFile = False

    if numReplaced == 0:
        print(\"No matched string to replace.\")
        if dst != src:
            saveFile = True
    else:
        print(\"Replaced \" + str(numReplaced) + \" strings.\")
        saveFile = True

    encoding = \"utf_8\"
    if hasBom:
        encoding = \"utf_8_sig\"

    if saveFile:
        with open(dst, \"wt\", encoding=encoding) as f:
            for line in dstLines:
                f.write(line + \"\n\")

    
"'







EOF

# メモ: python プログラムのインチキ・エイリアスの作成方法
# 
# 1. 先頭の cat <<\EOF | python3 と末尾の EOF を消す。
# 2. "   を   \"        に置換する。
# 3. '   を   '"'"'    に置換する。
# 4. 先頭に
#    alias command_name='python3 -c "
#    末尾に
#    "'
#    と書く。
# 
# 糸冬了！！


# メモ
# awk 活用
# cat a.txt | tee /dev/tty | xargs -n 1 -P 1 -IXXX bash -c 'id=$(echo -n "XXX" | awk "{printf \"%s\", \$1;}"); if [ $(echo -n $id | wc -m) -eq 64 ]; then echo a; echo "### Volume Container List for:"; echo "Volume: XXX"; docker ps -a --filter volume="$id"; fi'

chmod 755 /etc/profile.d/dn_benri_aliases.sh

touch ~/.bashrc_addtional

if [ $(cat ~/.bashrc_addtional | grep -F /etc/profile.d/dn_benri_aliases.sh | wc -l) -eq 0 ]; then
cat <<\EOF_BASHRC_ADDITIONAL >> ~/.bashrc_addtional

# Added by .dn_benri_install_or_update_main.sh
. /etc/profile.d/dn_benri_aliases.sh

EOF_BASHRC_ADDITIONAL
fi

### ブラケットペーストモードの無効化
touch ~/.inputrc
c1=$(cat ~/.inputrc | grep -F enable-bracketed-paste | wc -l)
if [ $c1 -eq 0 ]; then
cat <<\EOF_INPUTRC >> ~/.inputrc
set enable-bracketed-paste off
EOF_INPUTRC
fi


### ============= 便利ユーティリティ (root 用) ここから =============
if [[ $EUID -eq 0 ]]; then

if [ $(dpkg -l | grep -F tcptraceroute | wc -l) -eq 0 ]; then
  apt-get -y update && apt-get -y install tcptraceroute
fi

if [ $(dpkg -l | grep -F iputils-arping | wc -l) -eq 0 ]; then
  apt-get -y update && apt-get -y install iputils-arping
fi

if [ $(dpkg -l | grep -F " pv " | wc -l) -eq 0 ]; then
  apt-get -y update && apt-get -y install pv
fi

if [ ! -e /usr/bin/tcping ]; then
  curl --fail --insecure --pinnedpubkey "sha256//lvnOVgA0u06WySztudkn+urQda/zFBRd65A5wCmcBpQ=" --raw -o /usr/bin/tcping https://static2.lts.dn.ipantt.net/d/210114_001_misc_images_and_files_14723/Scripts/tcpping/tcpping
  chmod 755 /usr/bin/tcping
fi

if [ ! -e /usr/bin/tcpping ]; then
  curl --fail --insecure --pinnedpubkey "sha256//lvnOVgA0u06WySztudkn+urQda/zFBRd65A5wCmcBpQ=" --raw -o /usr/bin/tcpping https://static2.lts.dn.ipantt.net/d/210114_001_misc_images_and_files_14723/Scripts/tcpping/tcpping
  chmod 755 /usr/bin/tcpping
fi

if [ ! -e /usr/bin/pps2 ]; then
  curl --fail --insecure --pinnedpubkey "sha256//lvnOVgA0u06WySztudkn+urQda/zFBRd65A5wCmcBpQ=" --raw -o /usr/bin/pps2 https://static2.lts.dn.ipantt.net/d/210114_001_misc_images_and_files_14723/Scripts/pps2/pps2
  chmod 755 /usr/bin/pps2
fi

curl --fail --insecure --pinnedpubkey "sha256//lvnOVgA0u06WySztudkn+urQda/zFBRd65A5wCmcBpQ=" --raw https://static2.lts.dn.ipantt.net/d/210111_003_ubuntu_setup_scripts_59867/files/se_generate_login_banner.sh > /bin/se_generate_login_banner
chmod 755 /bin/se_generate_login_banner


fi
### ============= 便利ユーティリティ (root 用) ここまで =============


echo 

echo Install or Update Benri Scripts OK !!

echo 


# ping -O -i 0.3 192.168.3.2
