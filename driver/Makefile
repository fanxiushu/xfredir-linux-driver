# By Fanxiushu 2016 09-27
#

obj-m += xfsredir.o
xfsredir-objs := xfs_redir.o common.o ioctl.o xfs_dir.o xfs_file.o xfs_inode.o

KERNEL_DIR=/lib/modules/$(shell uname -r)/build
PWD=$(shell pwd)

all:
	make -C $(KERNEL_DIR) SUBDIRS=$(PWD) modules
clean:
	-rm -fr *.mod.c *.ko *.o .* *.order *.symvers
