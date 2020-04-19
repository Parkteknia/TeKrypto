# TeKrypto
Una clase Python para encriptar y desencriptar un directorio y con posibilidad de enviarlo a un servidor remoto por FTP.

## Características
Es una clase escrita para trabajar en un entorno limitado a Python 2.6 y testeada solo hasta Python 2.7 así que a menos que por arte de magia todo funcione en versiones superiores o que en el núcleo de tu sistema ya tengas Python 2.7, por ahora lo ideal es crear un *virtualenv* con python 2.7.

La clase permite:
* La creación del par de llaves privada/pública
* La encriptación y desencrptación mediante cifrado AES (Advanced Encryption Standard) de archivos/directorios
* El envío mediante FTP (También se ha tenido que optar por FTP por limitaciones del entorno).

## Requerimientos
La clase requiere el paquete [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/installation.html "PyCryptodome's Installation") el cual instala Crypto v. 3.9.7. y el resto de módulos necesarios.

```shell
pip install pycryptodome
```
## Instalación
La clase no requiere instalación, únicamente descarga los archivos o clónalos con git y ya.

## Uso

```python
from TeKrypto import Tekripto

# Ver la documentación en la propia clase

# Instancia la clase
Crypto = TeKrypto()

# Generar llaves (nombre de las llaves sin extensión y el tamaño de la llave)
Crypto.generaLLaves('mi_llave_privada', 'mi_llave_publica', 4096)

# Selecciona la llave pública con la que encriptar
Crypto.usaLlave('mi_llave_publica.pem', 'public')

# Encriptar un archivo 
Crypto.encriptaArchivo("archivo.pdf", False)

# Encriptar un directorio
Crypto.encriptaDirectorio("directorio", False)


# Selecciona la llave privada con la que desencriptar
Crypto.usaLlave('mi_llave_privada.pem', 'private')

# Desencripta un archivo
Crypto.desencriptaArchivo("archivo.pdf.crypt", False)

# Desencripta un direcotrio
crypt.desencriptaDirectorio("data/Documentos", False)

# Sube directorio/archivo por FTP
Crypto.ftp("data/")
```
## FTP

La configuración del FTP en el archivo FTP.py
