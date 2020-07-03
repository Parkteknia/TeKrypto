<img
src="https://github.com/Arteknia/TeKrypto-Docs/blob/master/01.png"
alt="TeKrypto Home"
/>

# TeKrypto
Una clase Python para encriptar y desencriptar datos.

## Características

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

Lo primero es crear el par de llaves privada/publica.

Para crear las llaves se ejectua desde la terminal y se indican los nombres de las llaves:

```shell
python3 TeKrypto.py -a generate_keys
Generating keys -->
Enter the name of the private key file without extension 'private_key_name': private
Private Key Name: private.key
Enter the name of the public key file without extension 'public_key_name': public
Public Key Name: public.key
The keys are generated and stored in the folder keys/
```

Una vez se han generado el par de llaves, para encriptar un archivo o directorio se ejecuta de la siguiente forma:
```python
python3 TeKrypto.py -a encrypt
Indicate the path of the file/directory to encrypt: /home/user/my_files/
Do you want to preserve the unencrypted file/directory? Type 'y' for yes and 'n' for no. n
Indicate the name of the 'public_key.pem' with which you want to encrypt: public.pem
Directory/File successfully encrypted: /home/user/my_files/
```
Para desencriptar un directorio:

```python
python3 TeKrypto.py -a decrypt
Indicate the path of the directory/file to decrypt: /home/user/my_files/
Do you want to preserve the decrypted directory/file? Type 'y' for yes and 'n' for no. n
Indicate the name of the 'private_key.pem' with which you want to decrypt: private.pem
Directory successfully decrypted: /home/user/my_files/
```

## FTP

* En desarrollo
