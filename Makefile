obj-m += lkmfirewall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean: fwhelper
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm fwhelper
test:
	sudo insmod lkmfirewall.ko
	sudo rmmod lkmfirewall
	dmesg
helper: fwhelper.cpp
	g++ -g fwhelper.cpp -o fwhelper
