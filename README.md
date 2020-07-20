<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0103.png"
alt="TeKrypto Home"
/>

# TeKrypto v1.0.3
Una clase Python para encriptar y desencriptar datos.

## Características

La clase permite:
* La creación del par de llaves privada/pública
* La encriptación y desencriptación de archivos/directorios mediante cifrado <a href="https://es.wikipedia.org/wiki/Advanced_Encryption_Standard" title="Advanced Encryption Standar">AES (Advanced Encryption Standard)</a> y el modo <a href="https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/proposed-modes/eax/eax-spec.pdf" title="EAX">EAX</a> disponible en PyCryptodome.
* La encriptación de los nombres de archivo

## Requerimientos
La clase requiere el paquete [PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/src/installation.html "PyCryptodome's Installation") el cual instala Crypto v. 3.9.7.

```shell
pip install pycryptodome
```
## Configuración y modos de utilización
* En la versión 1.0.3 se añade la capacidad de encriptar los nombres de archivo.
* En la versión 1.0.2 se ha añadido la posibilidad de configurar mediante el archivo config.ini algunos parámetros.

Se comentan las variables de la sección General y Keys de configuración del archivo config.ini:
```shell
[General]
Mode: Manual
EncryptNames: True
DefaultDataPath:
PreserveFiles:

[Keys]
KeysPath:
PrivateKey:
PublicKey:
```
##### Mode: (Test, Manual, Semi-Manual, Automate)
En esta versión los únicos modos funcionales son el Test y el Manual. En breve el resto.
##### EncryptNames: (False, True)
Para encriptar también los nombres de los archivos.
##### DefaultDataPath: (Absolute Path, c:/data_folder or /home/user/data_folder, etc.)
Si quieres indicar la ruta absoluta donde se encuentra tu carpeta de datos, de este modo cuando encriptas o desencriptas puedes indicar solo el nombre de la carpeta con la que quieres trabajar sin necesidad de indicar la ruta absoluta. Tambien será necesario para correr en modo Automate.
##### PreserveFiles: (False, True)
Para que no se eliminen los archivos durante el proceso (TODO: activarlo a través del config, solo funciona el preserve en modo manual.)
##### KeysPath: (Absolute Path, c:/files or /home/user/files, etc.)
Si quieres mantener tus llaves en otra hubicación puedes indicar la ruta absoluta a tu repositorio de llaves.
## Uso en modo "Test"

El modo test se ha incluído para tareas de desarrollo, pero dependiendo del uso que se le quiera dar a TeKrypto puede ser útil para realizar llamadas directas a las funciones. De momento si configuras desde el config.ini el Mode: Test, deberás escribir tus funciones a partir de la línea 561 del archivo TeKrypto.py.

## Uso en modo "Manual"

Lo primero es crear el par de llaves privada/publica.

### Generación de Llaves

Para crear las llaves se ejectua desde la terminal y se indican los nombres de las llaves:

```shell
python3 TeKrypto.py --action generate_keys
```
<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0103-generate-keys.png"
alt="TeKrypto Generating Keys"
/>

### Encriptación de datos

Una vez se han generado el par de llaves, para encriptar un archivo o directorio se ejecuta de la siguiente forma:
```shell
python3 TeKrypto.py --action encrypt
```
<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0103-encrypting.png"
alt="TeKrypto Generating Keys"
/>

Si se ha puesto a True la variable EncryptNames en el archivo de configuración config.ini, el archivo encriptado tendrá la siguiente forma para cada fichero cuyo nombre de archivo también se quiera encriptar. Si se observa, el primero de la lista es el que contiene los datos encriptados, el resto de archivos de un tamaño de 0 bytes, se usan para poder guardar el nombre encriptado y poder desencriptarlo en un futuro.

Se ha tenido que optar por esta solución debido a la longitud que adopta un string encriptado mediante el algoritmo que usa TeKrypto y las limitaciones en cuanto a longitud máxima para nombres de archivo en los diferentes S.O.

Cada nombre de archivo con nombre encryptado contiene:
* Un identificador TCBATCH {1595188009} que indica los archivos únicos que le pertenecen.
* Un índice {-0-} que indica el orden correcto en que debe leerse la encryptación codificada (base16)
* Y la codificación  {...738295A870B980F0A3A90EFD233058E4ACD9C5AF...} (128 carácteres), seguida de la extensión .crypt.
```shell
TCBATCH1595188009-0-738295A870B980F0A3A90EFD233058E4ACD9C5AF41B3C389551F07D67EDEFA828382DDCFCD1D4864EFF443DEDACE4CC530B7743B044CBE0BFF2991736DCA4068.crypt
```
<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0103-encrypted-filenames.png"
alt="TeKrypto Generating Keys"
/>

### Desencriptación de datos

Para desencriptar un archivo/directorio:

```shell
python3 TeKrypto.py --action decrypt
```
<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/0103-decrypting.png"
alt="TeKrypto Generating Keys"
/>

## FTP y SFTP

* En desarrollo
