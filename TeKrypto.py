#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import argparse
import readline
import base64

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from libs.FTP import TeFTP


class Colorize:
	PURPLE = '\033[95m'
	CYAN = '\033[96m'
	DARKCYAN = '\033[36m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	END = '\033[0m'

class TeKrypto():


	######################################################################################
	#
	# Inicializa la clase y el objeto keys
	#
	#
	##


	def __init__(self):

		self.global_error = False
		self.keys_path = "keys/"
		self.keys = {'private': '', 'public': ''}

	######################################################################################
	#
	# Generar las llaves RSA
	#
	# Args:
	#	priv_key (str): El nombre de la llave privada sin extensión.
	#	pub_key  (str): El nombre de la llave pública sin extensión.
	#	 size	  (int): El tamaño de la llave (2048, 3072, 4096) bits.
	#
	#	Returns:
	#		bool: The return value. True for success, False otherwise.
	##

	def generaLLaves(self, priv_key, pub_key, size):

		# Llave privada
		llave = RSA.generate(size)
		llave_privada = llave.exportKey('PEM')

		# Guarda archivo/llave PEM privada
		self.keys['private'] = self.keys_path + priv_key + '.pem'
		self.guardaLlave(self.keys['private'], llave_privada)

		# Llave pública
		llave_publica = llave.publickey().exportKey('PEM')

		# Guarda archivo/llave PEM pública
		self.keys['public'] = self.keys_path + pub_key + '.pem'
		self.guardaLlave(self.keys['public'], llave_publica)

		print("The keys are generated and stored in the folder keys/:", self.keys)

	######################################################################################
	#
	# Función para encriptar archivo
	#
	# Args:
	#	archivo (str): El nombre del archivo donde se guardará la llave
	#	llave  (str): La llave
	##

	def guardaLlave(self, archivo, llave):

		file = open(archivo,"wb")
		file.write(llave)
		file.close()

	######################################################################################
	#
	# Setea la llave pública para encriptar
	#
	# Args:
	#	nombre_llave (str): El nombre de la llave pública
	#	tipo  (str): publica/privada
	##

	def usaLlave(self, nombre_llave, tipo):
		self.keys[tipo] = self.keys_path + nombre_llave

	######################################################################################
	#
	# Encriptar archivo
	#
	# Args:
	#	archivo (str): El nombre del archivo a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##

	def encriptaArchivo(self, archivo, preserva):

		rsa_public_key = RSA.importKey(open(self.keys['public']).read())
		self.rsa_public_key = PKCS1_OAEP.new(rsa_public_key)

		contenido = self.leeArchivo(archivo)

		if False == bool(preserva):
			to_delete = archivo
			archivo = archivo + ".crypt"

		session_key = get_random_bytes(16)
		enc_session_key = self.rsa_public_key.encrypt(session_key)

		cipher_aes = AES.new(session_key, AES.MODE_EAX)

		self.guardaArchivoEncriptado(archivo, contenido, enc_session_key, cipher_aes)


	######################################################################################
	#
	# Desencriptar archivo
	#
	# Args:
	#	archivo (str): El nombre del archivo a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##

	def desencriptaArchivo(self, archivo, preserva):

		#contenido = self.leeArchivo(archivo)
		contenido = open(archivo, "rb")
		nombre_archivo = archivo[:-6] #Eliminar .crypt del nombre

		rsa_private_key = RSA.importKey(open(self.keys['private']).read())
		self.rsa_private_key = PKCS1_OAEP.new(rsa_private_key)

		enc_session_key, nonce, tag, ciphertext = \
			[ contenido.read(x) for x in (rsa_private_key.size_in_bytes(), 16, 16, -1) ]

		# Decrypt the session key with the private RSA key
		try:
			session_key = self.rsa_private_key.decrypt(enc_session_key)
		except ValueError:
			session_key = False
			print(Colorize.RED + "ERROR: Are you trying to decrypt an unencrypted file?" + Colorize.END)

		if not session_key:
			self.global_error = True
			return False
		# Decrypt the data with the AES session key
		cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
		data = cipher_aes.decrypt_and_verify(ciphertext, tag)


		file_out = open(nombre_archivo, "wb")
		file_out.write(data)
		file_out.close()



	######################################################################################
	#
	# Encripta directorio
	#
	# Args:
	#	direcotrio (str): El nombre del directorio a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##

	def encriptaDirectorio(self, directorio, preserva):

		rootdir = directorio

		for folder, subs, files in os.walk(rootdir):
			with open(os.path.join('logs/python-outfile.txt'), 'w') as dest:
				for filename in files:
					self.encriptaArchivo(folder + "/" + filename, preserva)
					dest.write(folder + filename  + '\n')
					if False == preserva:
						os.remove(folder + "/" + filename)

	######################################################################################
	#
	# Desncripta directorio
	#
	# Args:
	#	direcotrio (str): El nombre del directorio a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##

	def desencriptaDirectorio(self, directorio, preserva):

		rootdir = directorio

		for folder, subs, files in os.walk(rootdir):
			with open(os.path.join('logs/python-outfile.txt'), 'w') as dest:
				for filename in files:
					#kk
					if(folder + "/" + filename != folder + "/" + 'python-outfile.txt'):
						if os.path.splitext(folder + "/" + filename)[1] != ".crypt":
							self.global_error = True
							break
						self.desencriptaArchivo(folder + "/" + filename, preserva)
						#dest.write(folder + filename  + '\n')
					if False == preserva:
						os.remove(folder + "/" + filename)

		if self.global_error == False:
			print(Colorize.YELLOW + "Directory successfully decrypted: " + Colorize.END + directorio)
		else:
			print(Colorize.RED + "It looks like you are trying to decrypt an unencrypted file or dir!" + Colorize.END + directorio)
	######################################################################################
	#
	# Lee contenido archivo
	#
	# Args:
	#	archivo (str): El nombre del archivo  a leer
	#
	# Returns:
	#	 arcvhio binario contents
	##

	def leeArchivo(self, archivo):

		file = open(archivo, "rb")
		contenido = file.read()
		file.close()
		return contenido

	######################################################################################
	#
	# Encripta y Guarda el Arcvhivo encriptado
	#
	# Args:
	#	archivo (str): El nombre del archivo  final encriptado
	#	contenido (binary): Contenido de archivo a encriptar
	#	enc_session_key (int): La session del proceso  de encriptamiento
	#	cipher_aes: El cipher AES
	#
	##

	def guardaArchivoEncriptado(self, archivo, contenido, enc_session_key, cipher_aes):

		file= archivo
		file_out = open(archivo, "wb")

		ciphertext, tag = cipher_aes.encrypt_and_digest(contenido)
		[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]


	######################################################################################
	#
	# Desencripta y Guarda el Arcvhivo desencriptado
	#
	# Args:
	#	archivo (str): El nombre del archivo  final encriptado
	#	contenido (binary): Contenido de archivo a encriptar
	#	enc_session_key (int): La session del proceso  de encriptamiento
	#	cipher_aes: El cipher AES
	#
	##

	def guardaArchivoDesencriptado(self, archivo, contenido):

		file= archivo
		with open(file, 'wb') as filetowrite:
			filetowrite.write(self.rsa_private_key.encrypt(contenido))

	def ftp(self, directorio):
		return TeFTP(directorio)

def validate_name(name):
	new_name = name
	if re.match("^[A-Za-z0-9_]+$", new_name):
		return True

def get_args():
	parser = argparse.ArgumentParser(description='TeKrypto v1.0 by Arteknia.org - 2020')
	parser.add_argument('-a','--action', type=str, required=True, help='Action to execute', choices=['generate_keys', 'encrypt', 'decrypt'])
	return parser.parse_args()

if __name__ == '__main__':

	banner  = base64.b64decode(f"CgogX19fX18gICAgXyAgX18gICAgICAgICAgICAgICAgIF8gICAgICAgIF8KfF8gICBffF9ffCB8LyAvXyBfXyBfICAgXyBfIF9fIHwgfF8gX19fIHwgfAogIHwgfC8gXyBcICcgL3wgJ19ffCB8IHwgfCAnXyBcfCBfXy8gXyBcfCB8CiAgfCB8ICBfXy8gLiBcfCB8ICB8IHxffCB8IHxfKSB8IHx8IChfKSB8X3wKICB8X3xcX19ffF98XF9cX3wgICBcX18sIHwgLl9fLyBcX19cX19fLyhfKQogICAgICAgICAgICAgICAgICAgIHxfX18vfF98CgogICAgICBUZUtyeXB0byAxLjAgYnkgQXJ0ZWtuaWEub3JnIC0gMjAyMAo=").decode()

	print(Colorize.YELLOW + Colorize.BOLD + "\n\n" + banner + Colorize.END)

	args = get_args()
	if args:
		if args.action == "generate_keys":
			print("Generating keys -->")
			while True:
				try:
					private_name = input("Enter the name of the private key file without extension 'private_key_name': ")
					if not private_name:
						continue
					if True != validate_name(private_name):
						continue
				except ValueError:
					print("error")
				else:
					print("Private Key Name: " + private_name + ".key")
					break
			while True:
				try:
					public_name = input("Enter the name of the public key file without extension 'public_key_name': ")
					if not public_name:
						continue
					if True != validate_name(public_name):
						continue
				except ValueError:
					print("error")
				else:
					print("Public Key Name: " + public_name + ".key")
					break

			# Instancia la clase
			Crypto = TeKrypto()

			# Generar llaves (nombre de las llaves sin extensión y el tamaño de la llave)
			Crypto.generaLLaves(private_name, public_name, 4096)

		elif args.action == "encrypt":

			while True:
				try:
					path = input("Indicate the path of the file/directory to encrypt: ")

					if not os.path.isdir(path) and not os.path.isfile(path):
						print("The directory or file does not exist")
						continue

				except ValueError:
					print("error")
				else:
					if os.path.isdir(path):
						type = "d"
					if os.path.isfile(path):
						type = "f"
					break

			while True:
				try:
					preserve = input("Do you want to preserve the unencrypted file/directory? Type 'y' for yes and 'n' for no. ")

					if preserve != "y" and preserve != "n":
						continue
				except ValueError:
					print("error")
				else:
					if preserve == "y":
						prsv = True
					if preserve == "n":
						prsv = False
					break

			while True:
				try:
					key = input("Indicate the name of the 'public_key.pem' with which you want to encrypt: ")
					if not os.path.isfile("keys/"+key):
						print("The key does not exist")
						continue
				except ValueError:
					print("error")
				else:
					break
			print(Colorize.YELLOW + "Starting encryption process -->" + Colorize.END)
			# Instancia la clase
			Crypto = TeKrypto()

			# Selecciona la llave pública con la que encriptar
			Crypto.usaLlave(key, 'public')

			if type == "f":
				# Encriptar un archivo
				Crypto.encriptaArchivo(path, prsv)

			if type == "d":
				# Encriptar un directorio
				Crypto.encriptaDirectorio(path, prsv)

			print(Colorize.YELLOW + "Directory/file successfully encrypted: " + Colorize.END + path)

		elif args.action == "decrypt":

			while True:
				try:
					path = input("Indicate the path of the directory/file to decrypt: ")

					if not os.path.isdir(path) and not os.path.isfile(path):
						print("The directory or file does not exist")
						continue

				except ValueError:
					print("error")
				else:
					if os.path.isdir(path):
						type = "d"
					if os.path.isfile(path):
						type = "f"
					break

			while True:
				try:
					preserve = input("Do you want to preserve the decrypted directory/file? Type 'y' for yes and 'n' for no. ")

					if preserve != "y" and preserve != "n":
						continue
				except ValueError:
					print("error")
				else:
					if preserve == "y":
						prsv = True
					if preserve == "n":
						prsv = False
					break

			while True:
				try:
					key = input("Indicate the name of the 'private_key.pem' with which you want to decrypt: ")
					if not os.path.isfile("keys/"+key):
						print("The key does not exist")
						continue
				except ValueError:
					print("error")
				else:
					break

			print(Colorize.YELLOW + "Starting decryption process -->" + Colorize.END)

			# Instancia la clase
			Crypto = TeKrypto()

			# Selecciona la llave pública con la que encriptar
			Crypto.usaLlave(key, 'private')

			if type == "f":
				# Desencriptar un archivo
				Crypto.desencriptaArchivo(path, prsv)

			if type == "d":
				# Desencriptar un directorio
				Crypto.desencriptaDirectorio(path, prsv)
