#!/bin/bash

set -eu

export DEBIAN_FRONTEND=noninteractive

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



# Docker 関係
alias dn_docker_show_containers='docker ps -a'
alias dn_docker_show_containers_size='docker ps -a -s'
alias dn_docker_show_containers_running='docker ps'
alias dn_docker_show_containers_running_size='docker ps -s'
alias dn_docker_show_containers_size_running='docker ps -s'
alias dn_docker_show_running_containers='docker ps'
alias dn_docker_show_running_containers_size='docker ps -s'

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

if [ -e ~/.bashrc_addtional ]; then
  if [ $(cat ~/.bashrc_addtional | grep -F /etc/profile.d/dn_benri_aliases.sh | wc -l) -eq 0 ]; then
cat <<\EOF_BASHRC_ADDITIONAL >> ~/.bashrc_addtional

# Added by .dn_benri_install_or_update_main.sh
. /etc/profile.d/dn_benri_aliases.sh

EOF_BASHRC_ADDITIONAL
  fi
fi

echo 

echo Install or Update Benri Scripts OK !!

echo 


