obj-m += lkmfirewall.o

all: fwhelper.cpp
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	g++ -g fwhelper.cpp -o fwhelper
clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm fwhelper config.dat
