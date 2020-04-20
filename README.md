# TeKrypto
Una clase Python para encriptar y desencriptar un directorio y con posibilidad de enviarlo a un servidor remoto por FTP.

## Características
Es una clase escrita para trabajar en un entorno limitado a Python 2.6 y testeada solo hasta Python 2.7 así que a menos que por arte de magia todo funcione en versiones superiores o que en el núcleo de tu sistema ya tengas Python 2.7, por ahora lo ideal es crear un *virtualenv* con python 2.7.
``diff

+ Se ha creado en la carpeta 3.5 el script actualizado para correr en Python 3.5+

```

La clase permite:
* La creación del par de llaves privada/pública
* La encriptación y desencrptación mediante cifrado AES (Advanced Encryption Standard) de archivos/directorios
* El envío mediante FTP (También se ha tenido que optar por FTP por limitaciones del entorno).

## TODO
* Incluir detalle de instalación virtualenv (MacOS, Windows...)
* Actualmente no encripta el nombre ni del archivo ni del direcotrio, solo el contenido. (Implementar)
* Añadir extensiones dinámicas
* Mejorar los destinos/directorio de ambos procesos encrypt/decrypt
* Mejorar el sistema de logs/preport de cada procesamiento
* Lanzado por CRON

## Requerimientos
La clase requiere el paquete [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/installation.html "PyCryptodome's Installation") el cual instala Crypto v. 3.9.7. y el resto de módulos necesarios.

```shell
pip install pycryptodome
```
## Instalación
La clase no requiere instalación, únicamente descarga los archivos o clónalos con git y ya.

## Uso

Por ejemplo el archivo test.py mejor comentar las acciones por partes:

```python
# se importa la clase
from TeKrypto import Tekripto

# Ver más documentación en la propia clase

# Instancia la clase
Crypto = TeKrypto()
```

Ahora para generar un par de llaves:

```python
# Generar llaves (nombre de las llaves sin extensión y el tamaño de la llave)
Crypto.generaLLaves('mi_llave_privada', 'mi_llave_publica', 4096)
```

Para comprimir un directorio:

```python
# Selecciona la llave pública con la que encriptar
Crypto.usaLlave('mi_llave_publica.pem', 'public')

# Encriptar un directorio
Crypto.encriptaDirectorio("directorio", False)

# O encriptar un archivo (comentada)
#Crypto.encriptaArchivo("archivo.pdf", False)
```

Para enviar un directorio por FTP:

```python
# Sube directorio/archivo por FTP
Crypto.ftp("data/")
```

Para desencriptar un directorio:

```python
# Selecciona la llave privada con la que desencriptar
Crypto.usaLlave('mi_llave_privada.pem', 'private')


# Desencripta un direcotrio
Crypt.desencriptaDirectorio("data/Documentos", False)

# O desencripta un archivo (comentada)
#Crypto.desencriptaArchivo("archivo.pdf.crypt", False)

```

Y para llamarlo el script simplemente desde la terminal:

```shell
python test.py o python3 test.py
```

## FTP

* La configuración del FTP en el archivo FTP.py
* Cada sesión FTP genera en el directorio FTP destino una carpeta con un nombre tipo: 2020-04-19 15:46:07 con los archivos/directorios encriptados dentro.
