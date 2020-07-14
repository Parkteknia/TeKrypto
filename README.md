<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0102.png"
alt="TeKrypto Home"
/>

# TeKrypto v1.0.2
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

Se comentan las variables de la sección General de configuración del archivo config.ini:
```shell
[General]
Mode: Manual 
EncryptNames: False 
KeysPath:
DefaultDataPath:
```
#### Mode: (Manual, Semi-Manual, Automate)
En esta versión el único modo, pero en la siguiente se podrán lanzar procesos automatizados, o aligerar el modo manual.
#### EncryptNames: (False, True)
Para encriptar también los nombres de los archivos. En esta versión el único modo activo es False, es decir no encrypta en nombre del archivo o directorio.
#### KeysPath: (Absolute Path, c:/files or /home/user/files, etc.)
Si quieres mantener tus llaves en otra hubicación puedes indicar la ruta absoluta a tu repositorio de llaves.
#### DefaultDataPath: (Absolute Path, c:/data_folder or /home/user/data_folder, etc.)
Si quieres indicar la ruta absoluta donde se encuentra tu carpeta de datos, de este modo cuando encriptas o desencriptas puedes indicar solo el nombre de la carpeta. Tambien será necesario para correr en modo Automate.

## Uso en modo "Manual"

Lo primero es crear el par de llaves privada/publica.

### Generación de Llaves

Para crear las llaves se ejectua desde la terminal y se indican los nombres de las llaves:

```shell
python3 TeKrypto.py --action generate_keys
```
<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0102-generate-keys.png"
alt="TeKrypto Generating Keys"
/>

### Encriptación de datos

Una vez se han generado el par de llaves, para encriptar un archivo o directorio se ejecuta de la siguiente forma:
```shell
python3 TeKrypto.py --action encrypt
```
<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0102-encrypting.png"
alt="TeKrypto Generating Keys"
/>
### Desencriptación de datos

Para desencriptar un archivo/directorio:

```shell
python3 TeKrypto.py --action decrypt
```
<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0102-decrypting.png"
alt="TeKrypto Generating Keys"
/>

## FTP y SFTP

* En desarrollo
