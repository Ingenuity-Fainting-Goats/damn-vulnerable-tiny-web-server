# sreturn-into-libc - lab2

This project is a binary exploiting lab based on this public repo [https://github.com/shenfeng/tiny-web-server](https://github.com/shenfeng/tiny-web-server)

___

## Build

```
docker build -t damn-vulnerable-tinywebserver-lab2 .
```

## Run
```
docker run --name damn-vulnerable-tinywebserver-lab2 -it -p 9999:9999 -d damn-vulnerable-tinywebserver-lab2

```

## Execute Server
```
docker exec -it damn-vulnerable-tinywebserver-lab2 /bin/bash
```

## Delete container
```
docker rm --force damn-vulnerable-tinywebserver-lab2   
```