# process_ghost

Este proyecto tiene por objetivo generar un POC de Process Ghosting en Rust.<br>
Tecnica presentdata por [Gabriel Landau](https://twitter.com/GabrielLandau): <br>
https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack

Modo de Uso

process_ghosting.exe  target  payload

target:  Proceso del que deseamos tomar environment y parametros para inyectar en nuestro proceso <br> 
payload:  Archivo ejecutable que deseamos inyectar en nuestro proceso.
<h1>Video Poc</h1>

[![Process GHosting ](img/process.png)](https://www.youtube.com/watch?v=R869MTTogqw)




![](img/proc_ghost.png)

Caracteristicas:
-
+ Artefactos de memoria como en  [Process Doppelgänging](https://github.com/hasherezade/process_doppelganging)
+ Payload mapeado como `MEM_IMAGE` (sin nombre: no linkeado a ningun archivo)
+ Secciones mapeados con permisos originales (no `RWX`)
+ Payload conectado al PEB como modulo principal
+ Inyeccion Remota soportada (Pero solo en un proceso recien creado)
+ El proceso es creado en un modulo sin nombre(`GetProcessImageFileName` retorna un string vacio)


<h1>Links de Inpsiración:</h1>

https://github.com/hasherezade/process_ghosting <br>
https://doc.rust-lang.org/stable/std/mem/fn.transmute.html

Este proyecto es únicamente para fines educativos y el autor no se hace responsable por su uso indebido.

