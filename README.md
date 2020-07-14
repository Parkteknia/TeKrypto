<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0102.png"
alt="TeKrypto Home"
/>

# TeKrypto v1.0
Una clase Python para encriptar y desencriptar datos.

## Características

La clase permite:
* La creación del par de llaves privada/pública
* La encriptación y desencrptación mediante cifrado AES (Advanced Encryption Standard) de archivos/directorios

## Requerimientos
La clase requiere el paquete [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/installation.html "PyCryptodome's Installation") el cual instala Crypto v. 3.9.7.

```shell
pip install pycryptodome
```
## Configuración y modos de utilización
En esta versión se ha añadido una funcionalidad nueva de configuración mediante el archivo config.ini, así TeCrypto podrá correr de forma manual, semi-manual y automatizada (para ser lanzado mediante CRON). Ahora solo está implementada la versión Manual.

## Uso en modo "Manual"

Lo primero es crear el par de llaves privada/publica.

### Generación de Llaves

Para crear las llaves se ejectua desde la terminal y se indican los nombres de las llaves:

```shell
python3 TeKrypto.py --action generate_keys
```
<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0102-generate-keys.png"
alt="TeKrypto Home"
/>

### Encriptación de datos

Una vez se han generado el par de llaves, para encriptar un archivo o directorio se ejecuta de la siguiente forma:
```shell
python3 TeKrypto.py -a encrypt
Directory/File successfully encrypted: /home/user/my_files/
```
### Desencriptación de datos

Para desencriptar un archivo/directorio:

```shell
python3 TeKrypto.py -a decrypt
```


## FTP y SFTP

* En desarrollo
