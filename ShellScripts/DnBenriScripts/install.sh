#!/bin/bash

# How to run this script:
# 
# sudo bash -c "bash <( curl --raw https://raw.githubusercontent.com/IPA-CyberLab/IPA-DN-Misc/main/ShellScripts/DnBenriScripts/install.sh )"

(rm -fr /tmp/tmp_002_dn_benri_install_or_update/ ; mkdir -p /tmp/tmp_002_dn_benri_install_or_update/ && cd /tmp/tmp_002_dn_benri_install_or_update/ && git clone --branch main https://github.com/IPA-CyberLab/IPA-DN-Misc.git && sudo bash -c "bash <( cat ./IPA-DN-Misc/ShellScripts/DnBenriScripts/.dn_benri_install_or_update_main.sh )" ); rm -fr /tmp/tmp_002_dn_benri_install_or_update/

