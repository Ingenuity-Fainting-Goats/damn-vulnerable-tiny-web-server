FROM ubuntu:latest
MAINTAINER Alessandro B. "rhpco"

RUN apt-get update
RUN apt-get install -y vim
RUN apt-get install -y clang-7 make  libc6 libc6-dev g++-multilib gdb --fix-missing
RUN apt-get install -y software-properties-common python-all-dev wget
RUN apt-get install -y swig flex bison git gcc g++ make pkg-config glib-2.0
RUN mkdir /opt/code
RUN cd /opt/code; git clone https://github.com/radare/radare2.git; cd radare2; ./sys/install.sh
RUN cd /opt/code; git clone https://github.com/longld/peda.git; echo "source /opt/code/peda/peda.py" >> ~/.gdbinit
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# 
# Docker doesn't support well known echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
# use this command in order to execute binary without ASLR like:
# root@c509b02b3f5f:/opt# execnoaslr /bin/ls
# Makefile  code  tiny-lab2  tiny.c
# Reference: https://linux-audit.com/linux-aslr-and-kernelrandomize_va_space-setting/
#
RUN echo "alias execnoaslr='setarch `uname -m` -R $1'" >> ~/.bashrc
WORKDIR /opt
COPY ./app .
RUN make
EXPOSE 9999