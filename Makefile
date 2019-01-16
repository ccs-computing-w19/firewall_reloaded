obj-m += lkmfirewall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
test:
	sudo insmod lkmfirewall.ko
	sudo rmmod lkmfirewall
	dmesg
