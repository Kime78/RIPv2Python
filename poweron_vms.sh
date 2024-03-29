for vm in $(seq 1 5);
do
	VBoxManage startvm "Debian$vm" --type headless
done
