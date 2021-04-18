#!/bin/bash

set -eu

export DEBIAN_FRONTEND=noninteractive

cat <<\EOF > /etc/profile.d/dn_benri_aliases.sh
# by dnobori

# Docker 関係
alias dn_docker_show_containers_and_volumes='docker system df -v | tee /dev/tty | xargs -n 1 -P 1 -IXXX bash -c '"'"'id=$(echo -n "XXX" | awk "{printf \"%s\", \$1;}"); if [ $(echo -n $id | wc -m) -eq 64 ]; then echo ; echo "### Volume Container List for:"; echo "Volume: XXX"; docker ps -a --filter volume="$id"; fi'"'"''

EOF

chmod 755 /etc/profile.d/dn_benri_aliases.sh

source /etc/profile.d/dn_benri_aliases.sh

echo 

echo Install OK !!


