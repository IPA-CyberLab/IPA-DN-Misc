#!/bin/bash

# How to run this script:
# 
# sudo bash -c "bash <( curl --raw https://raw.githubusercontent.com/IPA-CyberLab/IPA-DN-Misc/main/ShellScripts/DnBenriScripts/install.sh )" ; source /etc/profile.d/dn_benri_aliases.sh

(rm -fr /tmp/tmp_002_dn_benri_install_or_update/ ; mkdir -p /tmp/tmp_002_dn_benri_install_or_update/ && cd /tmp/tmp_002_dn_benri_install_or_update/ && git clone --branch main https://github.com/IPA-CyberLab/IPA-DN-Misc.git && cd /tmp/tmp_002_dn_benri_install_or_update/IPA-DN-Misc/ && echo && echo --- Script version info --- && git log -1 && echo &&  echo ------ && sudo bash -c "bash <( cat /tmp/tmp_002_dn_benri_install_or_update/IPA-DN-Misc/ShellScripts/DnBenriScripts/.dn_benri_install_or_update_main.sh )" ); rm -fr /tmp/tmp_002_dn_benri_install_or_update/

