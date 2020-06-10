#!/bin/bash
# This script inserts the SSA module into the kernel.
# It then copies the module into another file location.
# It copies another bash script into a location where it will be run on boot.
# After running this script once, the SSA will load automatically
# every time the system is booted.

mv ssa.ko /etc/modules-load.d/ssa.ko -f
insmod /etc/modules-load.d/ssa.ko
cp superscript /etc/init.d/superscript -f
crontab -l | grep -q '@reboot /etc/init.d/superscript &' \
|| (crontab -l 2>/dev/null; echo \
"@reboot /etc/init.d/superscript &") | crontab -
