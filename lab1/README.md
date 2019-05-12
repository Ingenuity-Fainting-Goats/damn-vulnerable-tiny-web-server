# Tiny-Webserver-lab1 - Stack overflow Basics

This project is a binary exploiting lab based on this public repo [https://github.com/shenfeng/tiny-web-server](https://github.com/shenfeng/tiny-web-server)

___

## Build

```
docker build -t tinywebserver-lab1 .
```

## Run
```
docker run --name tinywebserver-lab1 -it -p 9999:9999 -d tinywebserver-lab1

```

## Execute Server
```
docker exec -it tinywebserver-lab1 /bin/bash
```

## Delete container
```
docker rm --force tinywebserver-lab1   
```