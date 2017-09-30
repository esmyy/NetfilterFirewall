#KERN_DIR = /usr/src/kernels/2.6.18-53.el5-i686
#KERN_DIR = /usr/src/$(shell uname -r)
ccflags-y += -std=gnu99

KERN_DIR = /lib/modules/3.13.0-32-generic/build
myfw-objs := test.o
obj-m += NetfilterFirewall.o
all:
	make -C $(KERN_DIR) M=$(shell pwd) modules   
clean:                                  
	make -C $(KERN_DIR) M=$(shell pwd) modules clean
	rm -rf modules.order
	rm -f *.symvers

# make CFLAGS+=-std=c99