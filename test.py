from TeKrypto import TeKrypto

#Ver la documentación en la propia clase

# Instancia la clase
Crypto = TeKrypto()


# Selecciona la llave pública con la que encriptar
#Crypto.usaLlave('mi_llave_publica.pem', 'public')

# Encriptar un archivo 
#Crypto.encriptaArchivo("test/test.jpg", False)

# Encriptar un directorio
#Crypto.encriptaDirectorio("data/Documentos", False)


# Selecciona la llave privada con la que desencriptar
Crypto.usaLlave('mi_llave_privada.pem', 'private')

# Desencripta un archivo
Crypto.desencriptaArchivo("test/test.jpg.crypt", False)

# Desencripta un direcotrio
#crypt.desencriptaDirectorio("data/Documentos", False)

# Sube directorio/archivo por FTP
#Crypto.ftp("data/")
