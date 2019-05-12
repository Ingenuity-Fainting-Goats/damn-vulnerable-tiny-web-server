FROM ubuntu:latest
MAINTAINER Alessandro B. "rhpco"

RUN apt-get update
RUN apt-get install -y clang
RUN apt-get install -y make
RUN apt-get install -y libc6 libc6-dev
RUN apt-get install -y g++-multilib
RUN apt-get install -y gdb

# export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
WORKDIR /opt
COPY ./app .
RUN make
RUN  echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
EXPOSE 9999