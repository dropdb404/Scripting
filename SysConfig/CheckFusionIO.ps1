
$fct0dr = fio-status /dev/fct0 -a | sls "Adapter: ioMono  \(driver "
$fct0fw = fio-status /dev/fct0 -a | sls "firmware"
$fct0pw = fio-status /dev/fct0 -a | sls "PCIe Power Limit threshold"
$fct0sn = fio-status /dev/fct0 -a | sls "ioMemory Adapter Controller, Product Number:831739-B21, SN:"
$fct1dr = fio-status /dev/fct1 -a | sls "Adapter: ioMono  \(driver " 
$fct1fw = fio-status /dev/fct1 -a | sls "firmware"
$fct1pw = fio-status /dev/fct1 -a | sls "PCIe Power Limit threshold"
$fct1sn = fio-status /dev/fct1 -a | sls "ioMemory Adapter Controller, Product Number:831739-B21, SN:"

write-host Device  Driver Firmware Power "  "S/N
echo ""
write-host "fct0  " $fct0dr.ToString().Split(" "")")[4] " " $fct0fw.ToString().Split(" ""v"",")[2] " "  $fct0pw[0].ToString().Split(" ")[4] $fct0sn[0].ToString().Split(":")[2]
echo ""
write-host "fct1  " $fct1dr.ToString().Split(" "")")[4] " " $fct1fw.ToString().Split(" ""v"",")[2] " "  $fct1pw[0].ToString().Split(" ")[4] $fct1sn[0].ToString().Split(":")[2]