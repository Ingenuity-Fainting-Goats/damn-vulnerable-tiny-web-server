# Writeup - Stack Buffer Overflow Basics - lab1

___

## Build

```
docker build -t damn-vulnerable-tinywebserver-lab1 .
```

## Run
```
docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined --name damn-vulnerable-tinywebserver-lab1 -it -p 9999:9999 -d damn-vulnerable-tinywebserver-lab1 

```
## Open server SHELL
```
docker exec -it damn-vulnerable-tinywebserver-lab1 /bin/bash
```

**!!!!!!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!!!!!**

Execute the vulnerable Web Server using following commands:

**!!!!!!!!!!!!!!!!! IMPORTANT !!!!!!!!!!!!!!!!!**

### Execute Vulnerable Tiny Web Server
Docker doesn't support the well known command useful to disable ASLR
```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```
So, use the command `execnoaslr` in order to execute target binary without ASLR support.
Usage example:
```
root@c509b02b3f5f:/opt# execnoaslr <TARGET_COMMAND_HERE>
```
Reference: https://linux-audit.com/linux-aslr-and-kernelrandomize_va_space-setting/

#### Tiny-lab1 Server execution:
Usage:
```
root@c509b02b3f5f:/opt# execnoaslr tiny-lab1
```
#### Tiny-lab1 Server DEBUG execution:
Usage:
```
root@c509b02b3f5f:/opt# execnoaslr gdb tiny-lab1
```

## Stop container
```
docker kill damn-vulnerable-tinywebserver-lab1   
```

## Delete container
```
docker rm --force damn-vulnerable-tinywebserver-lab1   
```

___
This project is a binary exploiting lab based on this public repo [https://github.com/shenfeng/tiny-web-server](https://github.com/shenfeng/tiny-web-server)
