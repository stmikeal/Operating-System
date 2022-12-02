obj-m := custom_data.o
KERNEL_PATH  := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	make -C $(KERNEL_PATH) M=$(PWD) modules
	sudo insmod ./custom_data.ko
	chmod 777 /proc/custom_data
	make -C $(KERNEL_PATH) M=$(PWD) clean
	rm -f Module.symvers
clean:
	rmmod custom_data
	
