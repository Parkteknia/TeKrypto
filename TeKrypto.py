#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import platform
import re
import configparser
import argparse
import readline
import base64

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from libs.FTP import TeFTP

from libs.Banner import get_banner

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
		self.keys_path = self.load_config('General', 'KeysPath')
		self.data_path = self.load_config('General', 'DefaultDataPath')
		self.keys = {'private': '', 'public': ''}
		self.mode = self.load_config('General', 'Mode')
		self.computer = self.load_platform()


	######################################################################################
	#
	# Carga el archivo de configuración
	#
	#
	##

	def load_config(self, section, param):
		config = configparser.ConfigParser()
		config._interpolation = configparser.ExtendedInterpolation()
		try:
			config.read("config/config.ini")
		except Exception as ErrorConfig:
			print(Colorize.RED + ErrorConfig + Colorize.END)

		if param == "KeysPath":
			kpath = config.get(section, param)
			if not kpath:
			    return os.path.dirname(os.path.realpath(__file__)) + "/keys/"
			return kpath
		return config.get(section, param)

	######################################################################################
	#
	# Load Operating System information
	#
	#
	##

	def load_platform(self):
		system = {'os': platform.system(), 'release': platform.release()}

		return system


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

		print(Colorize.GREEN +  "Keys stored in the " + Colorize.END + "keys/" + Colorize.GREEN + " folder:" + Colorize.END, self.keys)

	######################################################################################
	#
	# Key Exist
	#
	# Args:
	#	key_name
	#
	#	Returns:
	#		bool: True/False
	##

	def keyExist(self, key_name):
		if os.path.exists(self.keys_path + key_name + ".pem"):
			return True

	######################################################################################
	#
	# Validate key name
	#
	# Args:
	#	name
	#
	#	Returns:
	#		bool: True/False
	##

	def validate_key_name(self, name):
		new_name = name
		if re.match("^[A-Za-z0-9_]+$", new_name):
			return True

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


def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('--action', type=str, required=True, help='Action to execute', choices=['generate_keys', 'encrypt', 'decrypt'])
	return parser.parse_args()

if __name__ == '__main__':

	# Print TeKrypto Banner
	banner  = base64.b64decode(get_banner('1.0.2')).decode()
	print(Colorize.YELLOW + Colorize.BOLD + "\n\n" + banner + Colorize.END)

	# Create TeKrypto object
	Crypto = TeKrypto()

    #Print mode and environment info
	print(Colorize.GREEN + "TeKrypto is configured in " + Colorize.END + Colorize.BOLD + Crypto.mode + Colorize.END + Colorize.GREEN  + " mode ->" + Colorize.END)
	print(Colorize.GREEN + "Running in a " + Colorize.END + Colorize.BOLD + Crypto.computer['os'] + " " + Crypto.computer['release'] + Colorize.END + Colorize.GREEN  + " machine ->" + Colorize.END)
	print("")

	# Read args
	args = get_args()


	if Crypto.mode == 'Manual':
		if args:
			if args.action == "generate_keys":
				print(Colorize.YELLOW + "Generating keys -->" + Colorize.END)
				while True:
					try:
						private_name = input("Enter the private_key name with no extension 'private_key_name': ")
						if not private_name:
							continue
						if True != Crypto.validate_key_name(private_name):
							continue
						if True == Crypto.keyExist(private_name):
							print(Colorize.RED + "Warning! Key name already exists. Do you want to overwrite it?" + Colorize.END)
							override_confirm = input("Enter [y|n]: ")
							if override_confirm != "y" and override_confirm != "n":
								continue
							if override_confirm == "y":
								pass
							elif override_confirm == "n":
								print(Colorize.RED + "Operation cancelled!" + Colorize.END)
								exit()

					except ValueError:
						print("error")
					else:
						print(Colorize.GREEN + "Private Key Name: " + Colorize.END + private_name + ".pem")
						break
				while True:
					try:
						public_name = input("Enter the public_key name file with no extension 'public_key_name': ")
						if not public_name:
							continue
						if True != Crypto.validate_key_name(public_name):
							continue
						if True == Crypto.keyExist(private_name):
							print(Colorize.RED + "Warning! Key name already exists. Do you want to overwrite it?" + Colorize.END)
							override_confirm = input("Enter [y|n]: ")
							if override_confirm != "y" and override_confirm != "n":
								continue
							if override_confirm == "y":
								pass
							elif override_confirm == "n":
								print(Colorize.RED + "Operation cancelled!" + Colorize.END)
								exit()

					except ValueError:
						print("error")
					else:
						print(Colorize.GREEN + "Public Key Name: " + Colorize.END + public_name + ".pem")
						break

				# Generar llaves (nombre de las llaves sin extensión y el tamaño de la llave)
				Crypto.generaLLaves(private_name, public_name, 4096)

			elif args.action == "encrypt":
				print(Colorize.YELLOW + "Encrypting -->" + Colorize.END)
				while True:
					try:
						path = input("Indicate the path of the file/directory to encrypt: ")
						encrypt_path = Crypto.data_path + path
						print(encrypt_path)
						if not os.path.isdir(encrypt_path) and not os.path.isfile(encrypt_path):
							print("The directory or file does not exist")
							continue

					except ValueError:
						print("error")
					else:
						if os.path.isdir(encrypt_path):
							type = "d"
						if os.path.isfile(encrypt_path):
							type = "f"
						break

				while True:
					try:
						preserve = input("Do you want to preserve the unencrypted file/directory? Type [y|n]. ")

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

				# Selecciona la llave pública con la que encriptar
				Crypto.usaLlave(key, 'public')

				if type == "f":
					# Encriptar un archivo
					Crypto.encriptaArchivo(encrypt_path, prsv)

				if type == "d":
					# Encriptar un directorio
					Crypto.encriptaDirectorio(encrypt_path, prsv)

				print(Colorize.YELLOW + "Directory/file successfully encrypted: " + Colorize.END + path)

			elif args.action == "decrypt":
				print(Colorize.YELLOW + "Decrypting -->" + Colorize.END)
				while True:
					try:
						path = input("Indicate the path of the directory/file to decrypt: ")
						decrypt_path = Crypto.data_path + path
						if not os.path.isdir(decrypt_path) and not os.path.isfile(decrypt_path):
							print("The directory or file does not exist")
							continue

					except ValueError:
						print("error")
					else:
						if os.path.isdir(decrypt_path):
							type = "d"
						if os.path.isfile(decrypt_path):
							type = "f"
						break
				while True:
					try:
						preserve = input("Do you want to preserve the decrypted directory/file? Type [y|n]. ")

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

				# Selecciona la llave pública con la que encriptar
				Crypto.usaLlave(key, 'private')

				if type == "f":
					# Desencriptar un archivo
					Crypto.desencriptaArchivo(decrypt_path, prsv)

				if type == "d":
					# Desencriptar un directorio
					Crypto.desencriptaDirectorio(decrypt_path, prsv)
