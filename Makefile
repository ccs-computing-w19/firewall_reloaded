obj-m += lkmfirewall.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean: fwhelper
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm fwhelper config.dat
helper: fwhelper.cpp
	g++ -g fwhelper.cpp -o fwhelper
