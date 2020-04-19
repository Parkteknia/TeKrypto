from TeKrypto import Tekripto

#Ver la documentación en la propia clase

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