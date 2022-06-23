# Damn Vulnerable Tiny Web Server

A deliberately insecure webserver for learning purpose, this project is a binary exploiting lab based on public source code [https://github.com/shenfeng/tiny-web-server](https://github.com/shenfeng/tiny-web-server)

## Binary Exploiting Techniques (x86 - 32bit)
- *lab1/* - Stack Buffer Overflow - Basic
- *lab2/* - Return to Libc - NX bypass
- *lab3/* - Return Oriented Programming with execve() payload - NX bypass + ASLR bypass (compiled static)

## What

Every labs has the same vulnerable webserver binary running on docker container, try to navigate through single labs and follow instructions. Following learning objectives will be covered:
- Stack Buffer Overflow basics
- Return-into-libc exploiting technique
- Return-oriented-programming exploiting technique
- NX & ASLR bypass exploiting technique
- AddressSanitizer tool
- SPIKE fuzzer 
- etc.. etc...

## Why
- For fun and (no) profit 
- Learn, Learn, Understand, Fail and Learn Again.

## Author
- rhpco - Alessandro B. - twitter.com/rhpco
- dgui17 - Giovanni 


