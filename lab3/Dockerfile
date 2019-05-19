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

WORKDIR /opt
COPY ./app .
# RUN make
EXPOSE 9999
