#!/bin/bash

set -eu

export DEBIAN_FRONTEND=noninteractive

cat <<\EOF > /etc/profile.d/dn_benri_aliases.sh
# by dnobori

# テスト
alias dn_test1='echo Test1 OK!'

# 便利関数の更新
alias dn_update_benri='bash -c "bash <( curl --raw https://raw.githubusercontent.com/IPA-CyberLab/IPA-DN-Misc/main/ShellScripts/DnBenriScripts/install.sh )" ; source /etc/profile.d/dn_benri_aliases.sh'

# Docker 関係
alias dn_docker_show_containers_and_volumes='docker system df -v | tee /dev/tty | xargs -n 1 -P 1 -IXXX bash --noprofile --norc -c '"'"'id=$(echo -n "XXX" | awk "{printf \"%s\", \$1;}"); if [ $(echo -n $id | wc -m) -eq 64 ]; then echo ; echo "### Volume Container List for:"; echo "Volume: XXX"; docker ps -a --filter volume="$id"; fi'"'"'; echo'

alias dn_docker_show_containers='docker ps -a'

alias dn_docker_show_containers_size='docker ps -a -s'

alias dn_docker_show_containers_running='docker ps'

alias dn_docker_show_containers_running_size='docker ps -s'
alias dn_docker_show_containers_size_running='docker ps -s'

EOF

chmod 755 /etc/profile.d/dn_benri_aliases.sh

echo 

echo Install or Update Benri Scripts OK !!

echo 


