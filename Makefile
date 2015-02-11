#
#	Project:	advkill
#	Author:		Aaron
#	Time:		20131008
#	Compile and run in BoTong router

RR_MODULE_NAME	=	adv-kill
RR_MODULE_OBJ	=	$(RR_MODULE_NAME).o
RR_MODULE_OBJS	=	advkill.o strcmd.o pkgoper.o advproc.o advhash.o advconfparse.o
PWD				=	`pwd`
GCC_PATH		=	/home/botong/hndtools-mipsel-uclibc-4.2.4/bin

obj-m := $(RR_MODULE_OBJ)
$(RR_MODULE_NAME)-objs := $(RR_MODULE_OBJS)

KDIR := /home/botong/linux-2.6

default:
	make CC=mipsel-linux-linux26-gcc LD=mipsel-linux-linux26-ld AR=mipsel-linux-linux26-ar RANLIB=mipsel-linux-linux26-ranlib -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.ko *.ko.unsigned *.mod.c *.mod.o *.o *.order *.symvers *.markers