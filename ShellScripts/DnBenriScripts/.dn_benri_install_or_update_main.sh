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
alias reboot='echo Rebooting forcefully. Syncing... ; sync ; sync ; sync ; echo Sync OK. Rebooting... ; sleep 0.5 ; /sbin/reboot --force'
alias rebootbios='echo Rebooting forcefully 2. Syncing... ; sync ; sync ; sync ; echo Sync OK. Rebooting with BIOS... ; sleep 0.5 ; echo 1 > /proc/sys/kernel/sysrq ; echo b > /proc/sysrq-trigger ; echo Perhaps triggered'

alias dn_danger_rebootkernel='echo Rebooting with kexec-reboot forcefully. Syncing... ; sync ; sync ; sync ; echo Sync OK. Rebooting with kexec-reboot... ; sleep 0.5 ; /usr/sbin/kexec-reboot -l -r'

alias rebootkernel='echo Rebooting with kexec-reboot forcefully. Syncing... ; sync ; sync ; sync ; echo Sync OK. Rebooting with kexec-reboot... ; sleep 0.5 ; /usr/sbin/kexec-reboot -l -r'

alias listen_public='netst -n | grep -F -i -e LISTEN -e "0.0.0.0" -e ":::" | grep -F -i -e tcp -e ud | grep -F -i -v "127.0.0.1:" | grep -F -i -v "::1:"'

alias listen2='netst -n | grep -F -i -e LISTEN -e "0.0.0.0" -e ":::" | grep -F -i -e tcp -e ud | grep -F -i -v "127.0.0.1:" | grep -F -i -v "::1:"'

alias public='netst -n | grep -F -i -e LISTEN -e "0.0.0.0" -e ":::" | grep -F -i -e tcp -e ud | grep -F -i -v "127.0.0.1:" | grep -F -i -v "::1:"'


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






alias dn_getdisk_by_id='python3 -c "
import os
import json
import subprocess
import inspect
import sys
import time as systime
import argparse
import shutil

from typing import List, Tuple, Dict, Set, Callable, TypeVar, Type
from datetime import timedelta, tzinfo, timezone, time, date, datetime



class Str:
    NEWLINE_CELF = \"\r\n\"
    NEWLINE_CR = \"\r\"
    NEWLINE_LF = \"\n\"

    # 文字列を大文字・小文字を区別して比較
    @staticmethod
    def IsSame(s1: str, s2: str) -> bool:
        return Str.StrCmp(s1, s2)

    @staticmethod
    def StrCmp(s1: str, s2: str) -> bool:
        s1 = Str.NonNull(s1)
        s2 = Str.NonNull(s2)
        return s1 == s2

    @staticmethod
    def Cmp(s1: str, s2: str) -> int:
        return Str.StrCmpRetInt(s1, s2)

    @staticmethod
    def StrCmpRetInt(s1: str, s2: str) -> int:
        s1 = Str.NonNull(s1)
        s2 = Str.NonNull(s2)
        if (s1 == s2):
            return 0
        if (s1 < s2):
            return 1
        return -1

    # 文字列を大文字・小文字を区別せずに比較
    @staticmethod
    def IsSamei(s1: str, s2: str) -> bool:
        return Str.StrCmpi(s1, s2)

    @staticmethod
    def StrCmpi(s1: str, s2: str) -> bool:
        s1 = Str.NonNull(s1).lower()
        s2 = Str.NonNull(s2).lower()
        return s1 == s2

    @staticmethod
    def Cmpi(s1: str, s2: str) -> int:
        return Str.StrCmpRetInti(s1, s2)

    @staticmethod
    def StrCmpRetInti(s1: str, s2: str) -> int:
        s1 = Str.NonNull(s1).lower()
        s2 = Str.NonNull(s2).lower()
        if (s1 == s2):
            return 0
        if (s1 < s2):
            return 1
        return -1
    
    # 複数の文字列を置換する
    @staticmethod
    def ReplaceMultiStr(src: str, replaceList: Dict[str, str], caseSensitive: bool = False) -> str:
        src = Str.NonNull(src)
        for key, value in replaceList.items():
            src = Str.ReplaceStr(src, key, value, caseSensitive)
        return src

    # 文字列を置換する
    @staticmethod
    def ReplaceStr(str: str, oldKeyword: str, newKeyword: str, caseSensitive: bool = False) -> str:
        str = Str.NonNull(str)
        if Str.IsNullOrZeroLen(str):
            return \"\"
        oldKeyword = Str.NonNull(oldKeyword)
        newKeyword = Str.NonNull(newKeyword)
        if Str.IsNullOrZeroLen(oldKeyword):
            return str

        i = 0
        j = 0
        num = 0
        sb = \"\"

        len_string = len(str)
        len_old = len(oldKeyword)
        len_new = len(newKeyword)

        while True:
            i = Str.SearchStr(str, oldKeyword, i, caseSensitive)
            if i == -1:
                sb += str[j:]
                break
            num += 1
            sb += str[j:i]
            sb += newKeyword

            i += len_old
            j = i

        return sb

    # 文字列を検索する
    @staticmethod
    def SearchStr(str: str, keyword: str, start: int = 0, caseSensitive: bool = False) -> int:
        str = Str.NonNull(str)
        keyword = Str.NonNull(keyword)
        if Str.IsNullOrZeroLen(str) or Str.IsNullOrZeroLen(keyword):
            return -1
        if not caseSensitive:
            str = str.lower()
            keyword = keyword.lower()
        return str.find(keyword, start)

    # 文字列が含まれるか?
    @staticmethod
    def InStr(str: str, keyword: str, caseSensitive: bool = False) -> bool:
        str = Str.NonNull(str)
        keyword = Str.NonNull(keyword)
        if Str.IsNullOrZeroLen(str) or Str.IsNullOrZeroLen(keyword):
            return False
        if not caseSensitive:
            str = str.lower()
            keyword = keyword.lower()
        return keyword in str

    @staticmethod
    def GetLines(src: str, removeEmpty: bool = False, trim: bool = False) -> List[str]:
        ret: List[str] = list()
        for line in Str.NonNull(src).splitlines():
            if trim:
                line = Str.Trim(line)

            if not removeEmpty or Str.IsFilled(line):
                ret.append(line)
        return ret

    @staticmethod
    def IsNullOrZeroLen(str: str) -> bool:
        if Str.IsNull(str) or len(str) == 0:
            return True
        return False

    @staticmethod
    def IsNull(str: str) -> bool:
        return Util.IsNull(str)

    @staticmethod
    def IsNonNull(str: str) -> bool:
        return not Str.IsNull(str)

    @staticmethod
    def ToStr(str: any) -> str:
        if Util.IsNull(str):
            return \"\"

        if Util.IsType(str, \"str\"):
            return str

        return F\"{str}\"

    @staticmethod
    def NonNull(str: str) -> str:
        if Str.IsNull(str):
            return \"\"

        return str

    @staticmethod
    def StrToInt(str: str) -> int:
        try:
            if Str.IsNull(str):
                return 0
            i = int(str)
            return i
        except:
            return 0

    @staticmethod
    def Trim(str: str) -> str:
        return Str.NonNull(str).strip()

    @staticmethod
    def IsEmpty(str: str) -> bool:
        if Str.Len(Str.Trim(str)) == 0:
            return True
        return False

    @staticmethod
    def IsFilled(str: str) -> bool:
        return not Str.IsEmpty(str)

    @staticmethod
    def Len(str: str) -> int:
        if Str.IsNull(str):
            return 0

        return len(str)

    @staticmethod
    def ToBool(str: str) -> bool:
        i = Str.StrToInt(str)
        if i != 0:
            return True

        tmp = Str.Trim(str).lower()

        if Str.Len(tmp) >= 1:
            if tmp[0] == '"'"'y'"'"' or tmp[0] == '"'"'t'"'"':
                return True
            if tmp.startswith(\"ok\") or tmp.startswith(\"on\") or tmp.startswith(\"enable\"):
                return True

        return False

    @staticmethod
    def GetStr(object: any) -> str:
        if object is None:
            return \"None\"

        if Util.IsTypeOf(object, str):
            return object

        if Util.IsTypeOf(object, Exception):
            return F\"{object}\"

        if Util.IsSimpleValue(object):
            return str(object)

        return Json.ObjectToJson(object)

    @staticmethod
    def Combine(strList: list, splitStr: str = \", \", removeEmpty: bool = False) -> str:
        ret = \"\"
        tmpList: List[str] = list()

        for item in strList:
            s = Str.GetStr(item)
            if not removeEmpty or Str.IsFilled(s):
                tmpList.append(s)

        num = len(tmpList)
        for i in range(num):
            ret += tmpList[i]

            if i != (num - 1):
                ret += splitStr

        return ret
    
    @staticmethod
    def GetFirstFilledLine(src: str) -> str:
        src = Str.GetStr(src)
        lines = Str.GetLines(src, removeEmpty=True, trim=True)
        for line in lines:
            return line
        return \"\"

    @staticmethod
    def OneLine(src: str, splitStr: str = \" / \", removeEmpty: bool = True) -> str:
        src = Str.GetStr(src)
        lines = Str.GetLines(src, removeEmpty=True, trim=True)
        return Str.Combine(lines, splitStr, removeEmpty)
    
    @staticmethod
    def NormalizeFqdn(src: str) -> str:
        s = Str.Trim(src).lower()
        tokens = s.split(\".\")
        o: List[str] = list()
        for token in tokens:
            if Str.IsFilled(token):
                for c in token:
                    if not ((c >= \"a\" and c <= \"z\") or (c >= \"0\" and c <= \"9\") or c == \"-\" or c == \"_\"):
                        raise Err(f\"Invalid FQDN: '"'"'{src}'"'"'\")
                o.append(token)
        ret = Str.Combine(o, \".\", removeEmpty=True)
        if Str.IsEmpty(ret):
            raise Err(f\"Invalid FQDN: '"'"'{src}'"'"'\")
        return ret
    
    @staticmethod
    def DecodeUtf8(src: bytes) -> str:
        if Util.IsNull(src):
            return \"\"
        return Str.NonNull(src.decode(\"utf-8\"))
    
    @staticmethod
    def EncodeUtf8(src: str) -> bytes:
        src = Str.NonNull(src)
        return src.encode(\"utf-8\")

def Print(obj: any) -> str:
    s = Str.GetStr(obj)
    print(s)
    return s

def PrintLog(obj:any) -> str:
    s = Str.GetStr(obj)
    print(f\"{Time.NowLocal()}: {s}\")
    return s


def GetStr(obj: any) -> str:
    return Str.GetStr(obj)

def DoNothing():
    return 0

def NoOp():
    return 0

class Util:
    @staticmethod
    def ToBool(object: any) -> bool:
        if Util.IsType(object, \"str\"):
            return Str.ToBool(str)

        if not (object):
            return False

        return True

    @staticmethod
    def IsNull(object: any) -> bool:
        if object is None:
            return True

        return False

    @staticmethod
    def GetTypeName(object: any) -> str:
        return type(object).__name__

    @staticmethod
    def IsType(object: any, typeName: str) -> bool:
        if Util.GetTypeName(object) == typeName:
            return True

        return False

    @staticmethod
    def IsTypeOf(object: any, baseType: type) -> bool:
        return isinstance(object, baseType)

    @staticmethod
    def IsBinary(object: any) -> bool:
        return Util.IsType(object, \"bytes\")

    @staticmethod
    def IsClass(object: any) -> bool:
        return hasattr(object, \"__dict__\")

    @staticmethod
    def IsPrimitive(object: any) -> bool:
        if Util.IsNull(object):
            return True
        return isinstance(object, (int, float, bool, str, bytes, bytearray, memoryview))

    @staticmethod
    def IsSimpleValue(object: any) -> bool:
        if Util.IsPrimitive(object):
            return True
        return isinstance(object, (datetime))

    @staticmethod
    def GetClassAttributes(object: any) -> dict:
        if Util.IsClass(object):
            return object.__dict__
        raise Err(\"Not a class object.\")

    @staticmethod
    def GetClassAttributesOrItself(object: any):
        if Util.IsClass(object):
            return Util.GetClassAttributes(object)
        return object
    
    @staticmethod
    def GenRandInterval(standard: float, plusMinusPercentage: float = 30.0) -> float:
        rate = plusMinusPercentage * (Rand.SInt31() % 10000) / 10000.0 / 100.0
        v = standard * rate
        if (v == 0.0):
            return standard
        b = Rand.Bool()
        if b:
            ret = standard + standard * rate
        else:
            ret = standard - standard * rate
        return max(ret, 0.001)
    
    @staticmethod
    def GetSingleHostCertAndIntermediateCertsFromCombinedCert(src: str) -> Tuple[str, str]:
        lines = Str.GetLines(src, trim=True)
        flag = 0

        cert0_body = \"\"
        cert1_body = \"\"

        current_cert = \"\"
        cert_index = 0

        for line in lines:
            if line == \"-----BEGIN CERTIFICATE-----\":
                flag = 1
                current_cert += line + \"\n\"
            elif line == \"-----END CERTIFICATE-----\":
                flag = 0
                current_cert += line + \"\n\"
                if cert_index == 0:
                    cert0_body = current_cert
                else:
                    cert1_body += current_cert
                    cert1_body += \"\n\"
                cert_index += 1
                current_cert = \"\"
            else:
                if flag == 1:
                    current_cert += line + \"\n\"
        
        return (cert0_body, cert1_body)

class EasyExecResults:
    Result: subprocess.CompletedProcess
    IsOk: bool
    StdOut: str
    StdErr: str
    StdOutAndErr: str
    ExitCode: int
    Cmd: List[str]

    def InitFromCompletedProcess(self, res: subprocess.CompletedProcess, cmd: List[str]):
        self.Result = res
        self.ExitCode = res.returncode
        self.IsOk = (res.returncode == 0)
        self.StdOut = Str.ToStr(res.stdout)
        self.StdErr = Str.ToStr(res.stderr)
        self.StdOutAndErr = self.StdOut + \"\n\" + self.StdErr + \"\n\"
        self.Cmd = cmd

    def ThrowIfError(self):
        if not self.IsOk:
            errOneLine = Str.OneLine(self.StdErr)
            outOneLine = Str.OneLine(self.StdOut)
            tmp = f\"Command '"'"'{self.Cmd}'"'"' returned exit code {self.ExitCode}.\"
            if Str.IsFilled(errOneLine):
                tmp += f\" Error string: {errOneLine}\"
            if Str.IsFilled(outOneLine):
                tmp += f\" Output string: {outOneLine}\"

            raise Err(tmp)


class EasyExec:
    @staticmethod
    # 注意! timeoutSecs でタイムアウトを指定し、タイムアウト発生時には kill するためには、shell = False にしなければならない。
    def Run(command: List[str], shell: bool = True, ignoreError: bool = False, timeoutSecs: int = None):
        if shell and timeoutSecs is not None:
            raise Err(\"shell == True and timeoutSecs is not None.\")

        res = subprocess.run(command, shell=shell,
                             encoding=\"utf-8\", text=True, timeout=timeoutSecs)
        
        if not ignoreError:
            res.check_returncode()

    @staticmethod
    # 注意! timeoutSecs でタイムアウトを指定し、タイムアウト発生時には kill するためには、shell = False にしなければならない。
    def RunPiped(command: List[str], shell: bool = True, ignoreError: bool = False, timeoutSecs: int = None) -> EasyExecResults:
        if shell and timeoutSecs is not None:
            raise Err(\"shell == True and timeoutSecs is not None.\")

        res = subprocess.run(command, shell=shell, encoding=\"utf-8\", text=True,
                             timeout=timeoutSecs, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        ret = EasyExecResults()
        ret.InitFromCompletedProcess(res, command)

        if not ignoreError:
            ret.ThrowIfError()

        return ret

    @staticmethod
    def RunBackground(command: List[str], shell: bool = True, cwd: str = None, stdin=None, stdout=None, stderr=None) -> subprocess.Popen:
        res = subprocess.Popen(command, shell=shell, text=True,
                               cwd=cwd, stdin=stdin, stdout=stdout, stderr=stderr)

        return res

class Err(Exception):
    def __init__(self, str: str):
        pass

if __name__ == '"'"'__main__'"'"':
    parser = argparse.ArgumentParser()
    parser.add_argument(\"id\", metavar=\"<id>\", type=str, help=\"Disk Id\")

    args = parser.parse_args()
    id = args.id

    result = EasyExec.RunPiped(\"/usr/sbin/fdisk -l\".split(), shell=False,
            timeoutSecs=30)

    lines = Str.GetLines(result.StdOut)

    mode = 0

    current_disk_name = \"\"

    dev_and_id_list = []

    dev_and_id_list.append((\"/dev/sdc\", \"123\"))

    for line in lines:
        line = Str.Trim(line)
        if Str.IsFilled(line):
            if mode == 0:
                current_disk_name = \"\"
                mode = 1
                if line.startswith(\"Disk /\"):
                    tmp1 = line[5:]
                    colon1_index = Str.SearchStr(tmp1, \":\")
                    if colon1_index >= 1:
                        tmp2 = tmp1[:colon1_index]
                        tmp2 = Str.Trim(tmp2)
                        current_disk_name = tmp2
            elif mode == 1:
                if Str.IsFilled(current_disk_name):
                    if line.startswith(\"Disk identifier:\"):
                        tmp1 = line[17:]
                        tmp1 = Str.Trim(tmp1)
                        dev_and_id_list.append((current_disk_name, tmp1))
        else:
            mode = 0
            current_disk_name = \"\"

    dev_and_id_list.append((\"/dev/sdb\", \"123\"))

    dev_and_id_list.sort(key=lambda x:x[0])

    ret = \"\"

    num = 0

    for element in dev_and_id_list:
        if Str.IsSamei(element[1], id):
            if Str.IsEmpty(ret):
                ret = element[0]
            num += 1


    if Str.IsEmpty(ret):
        ret = \"ERROR_NOT_FOUND_DISK_ID\"
    
    if num >= 2:
        ret = \"ERROR_DUPLICATED_DISK_ID\"

    print(ret)


    

    
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

if [ $(dpkg -l | grep -F kexec-tools | wc -l) -eq 0 ]; then
  apt-get -y update && apt-get -y install kexec-tools
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

curl --fail --insecure --pinnedpubkey "sha256//lvnOVgA0u06WySztudkn+urQda/zFBRd65A5wCmcBpQ=" --raw https://static2.lts.dn.ipantt.net/d/240301_001_85842/kexec-reboot_force.sh > /usr/sbin/kexec-reboot
chmod 755 /usr/sbin/kexec-reboot


fi
### ============= 便利ユーティリティ (root 用) ここまで =============


echo 

echo Install or Update Benri Scripts OK !!

echo 


# ping -O -i 0.3 192.168.3.2
