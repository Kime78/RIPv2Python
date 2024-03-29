for i in $(seq 1 5);
do
	VBoxManage controlvm "Debian$i" poweroff
done
