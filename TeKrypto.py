#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys
import calendar;
import time;
from datetime import datetime
import platform
import re
import configparser
import argparse
import readline
import base64


from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

from libs.Colorize import Colorize
from libs.Banner import get_banner

from libs.FTP import TeFTP


class TeKrypto():

	######################################################################################
	#
	# Inicializa la clase y el objeto keys
	#
	#
	##

	def __init__(self):

		self.global_error = False
		self.keys_path = self.load_config('Keys', 'KeysPath')
		self.data_path = self.load_config('General', 'DefaultDataPath')
		self.keys = {'private': '', 'public': ''}
		self.keys_log = self.load_config('Keys', 'KeysLog')
		self.encrypt_log = self.load_config('General', 'EncryptLog')
		self.decrypt_log = self.load_config('General', 'DecryptLog')
		self.mode = self.load_config('General', 'Mode')
		self.enames = self.load_config('General', 'EncryptNames')
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
		if param == "KeysLog":
			return config.getboolean(section, param)
		if param == "EncryptLog" or param == "DecryptLog":
			return config.getboolean(section, param)
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
	#	size	  (int): El tamaño de la llave (2048, 3072, 4096) bits.
	#
	#	Returns:
	#		bool: The return value. True for success, False otherwise.
	##

	def generateKeys(self, priv_key, pub_key, size):

		# Llave privada
		llave = RSA.generate(size)
		llave_privada = llave.exportKey('PEM')

		# Guarda archivo/llave PEM privada
		self.keys['private'] = self.keys_path + priv_key + '.pem'
		self.saveKey(self.keys['private'], llave_privada)

		# Llave pública
		llave_publica = llave.publickey().exportKey('PEM')

		# Guarda archivo/llave PEM pública
		self.keys['public'] = self.keys_path + pub_key + '.pem'
		self.saveKey(self.keys['public'], llave_publica)

		print(Colorize.GREEN +  "Keys stored in the " + Colorize.END + "keys/" + Colorize.GREEN + " folder:" + Colorize.END, self.keys)
		
		k = [self.keys['private'], self.keys['public']]

		if True == self.keys_log:
			self.saveLog("keys", k)
 
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

	def saveKey(self, archivo, llave):

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

	def useKey(self, nombre_llave, tipo):
		self.keys[tipo] = self.keys_path + nombre_llave

	######################################################################################
	#
	# Encriptar nombre archivo
	#
	# Args:
	#	archivo (str): El nombre del archivo cuyo nombre encriptar
	##

	def encryptFileName(self, filename):
		
		self.public_key = RSA.importKey(open("keys/public.pem").read())

		filename = filename.encode("utf-8")

		session_key = get_random_bytes(16)
		
		cipher_rsa = PKCS1_OAEP.new(self.public_key)
		enc_session_key = cipher_rsa.encrypt(session_key)

		cipher_aes = AES.new(session_key, AES.MODE_EAX)
		ciphertext, tag = cipher_aes.encrypt_and_digest(filename)
		data = b"".join([x for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)])
		
		return base64.b16encode(data).decode("utf-8")
		
	######################################################################################
	#
	# Desencriptar nombre archivo
	#
	# Args:
	#	archivo (str): El nombre del archivo cuyo nombre desencriptar
	##

	def decryptFileName(self, c):
		
		self.private_key = RSA.importKey(open("keys/private.pem").read())
		
		enc_session_key = c[:self.private_key.size_in_bytes()]
		nonce = c[self.private_key.size_in_bytes():self.private_key.size_in_bytes()+16]
		tag = c[self.private_key.size_in_bytes()+16:self.private_key.size_in_bytes()+32]
		ciphertext = c[self.private_key.size_in_bytes()+32:]

		cipher_rsa = PKCS1_OAEP.new(self.private_key)
		session_key = cipher_rsa.decrypt(enc_session_key)

		cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
		data = cipher_aes.decrypt_and_verify(ciphertext, tag)

		return data.decode("utf-8")

	######################################################################################
	#
	# Encriptar archivo
	#
	# Args:
	#	archivo (str): El nombre del archivo a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##

	def encryptFile(self, archivo, preserva):

		rsa_public_key = RSA.importKey(open(self.keys['public']).read())
		self.rsa_public_key = PKCS1_OAEP.new(rsa_public_key)

		contenido = self.readFile(archivo)
		
		origin_file = archivo

		archivo = archivo + ".crypt"

		session_key = get_random_bytes(16)
		enc_session_key = self.rsa_public_key.encrypt(session_key)

		cipher_aes = AES.new(session_key, AES.MODE_EAX)

		self.saveEncryptedFile(archivo, contenido, enc_session_key, cipher_aes)
				
		if self.enames:
			file_path = self.getFilenameAndPath(archivo)
			ename = self.encryptFileName(file_path[1][:-6])
			self.saveBatchedFile(file_path[0], archivo, ename)
			
		
		if True == self.encrypt_log:
			self.saveLog("encrypt", origin_file)

	######################################################################################
	#
	# Desencriptar archivo
	#
	# Args:
	#	archivo (str): El nombre del archivo a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##

	def decryptFile(self, archivo, preserva):
		
		decompose_file = self.getFilenameAndPath(archivo)
				
		bfile = self.extractBatchFile(decompose_file[1])
				
		if self.isBatchFile(decompose_file[1]):
			batch_info = self.extractBatchFile(decompose_file[1])
			unencrypted_name_code = self.readNameFromBatchFiles(decompose_file[0], batch_info[0])
			original_name = self.decryptFileName(unencrypted_name_code)
			self.removeBatchFiles(decompose_file[0], original_name, bfile[0])
			archivo = decompose_file[0] + "/" + original_name + ".crypt"
		
		contenido = open(archivo, "rb")
		nombre_archivo = archivo[:-6] #Eliminar .crypt del nombre

		rsa_private_key = RSA.importKey(open(self.keys['private']).read())
		self.rsa_private_key = PKCS1_OAEP.new(rsa_private_key)

		enc_session_key, nonce, tag, ciphertext = \
			[ contenido.read(x) for x in (rsa_private_key.size_in_bytes(), 16, 16, -1) ]
		
		if self.isBatchFile(decompose_file[1]):
			os.remove(nombre_archivo + ".crypt")
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
		
		if False == preserva:
			os.remove(archivo)



	######################################################################################
	#
	# Encripta directorio
	#
	# Args:
	#	direcotrio (str): El nombre del directorio a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##

	def encryptDirectory(self, directorio, preserva):

		rootdir = directorio

		for folder, subs, files in os.walk(rootdir):
			with open('logs/tekrypto-encrypt.log', 'a') as dest:
				dest.write(self.getCurrentDateTime() + " - Encrypted folder: " + folder  + '\n')
				for filename in files:
					self.encryptFile(folder + "/" + filename, preserva)
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

	def decryptDirectory(self, directorio, preserva):

		rootdir = directorio
		batched_files = []
		batched_timestamps = {}
		normal_files = []

		for folder, subs, files in os.walk(rootdir):
			with open(os.path.join('logs/python-outfile.txt'), 'w') as dest:
				for filename in sorted(files):
					#kk
					if(folder + "/" + filename != folder + "/" + 'python-outfile.txt'):
						if os.path.splitext(folder + "/" + filename)[1] != ".crypt":
							self.global_error = True
							break
						if self.isBatchFile(filename):
							timestamp_file = self.extractBatchFile(filename)[0]
							
							if timestamp_file not in batched_timestamps:
								batched_timestamps[timestamp_file] = {}
								batched_timestamps[timestamp_file]['files'] = []
								batched_timestamps[timestamp_file]['code'] = ""
								batched_timestamps[timestamp_file]['files'].append(folder + "/" + filename)
							else:
								batched_timestamps[timestamp_file]['files'].append(folder + "/" + filename)
		
		if len(batched_timestamps) != 0:
			self.prepareBatchFilesDecrypt(rootdir, batched_timestamps)
		
		
		for folder, subs, files in os.walk(rootdir):
			with open(os.path.join('logs/python-outfile.txt'), 'w') as dest:
				for filename in sorted(files):
					#kk
					if(folder + "/" + filename != folder + "/" + 'python-outfile.txt'):
						if os.path.splitext(folder + "/" + filename)[1] != ".crypt":
							self.global_error = True
							break
						self.decryptFile(folder + "/" + filename, preserva)
						dest.write(folder + filename  + '\n')
		
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

	def readFile(self, archivo):

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

	def saveEncryptedFile(self, archivo, contenido, enc_session_key, cipher_aes):

		file_out = open(archivo, "wb")

		ciphertext, tag = cipher_aes.encrypt_and_digest(contenido)
		[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

	######################################################################################
	#
	# Guarda los archivos necesarios para guardar el nombre del archivo codificado
	#
	# Args:
	#	file_data (str): La encriptación codificada en base16
	#
	##

	def saveBatchedFile(self, path, original_file, file_data):
		n = 128
		chunks = [file_data[i:i+n] for i in range(0, len(file_data), n)]
		timestamp = self.getTimeStamp()
		for i, c in enumerate(chunks):
			if i == 0:
				os.rename(original_file,path +"/TCBATCH"+str(timestamp)+"-"+str(i)+"-"+str(c)+".crypt")
				continue
			open(path + "/TCBATCH"+str(timestamp)+"-"+str(i)+"-"+str(c)+".crypt", 'a').close()
	
	######################################################################################
	#
	# Desencripta y Guarda el Arcvhivo desencriptado
	#
	# Args:
	#	archivo (str): El nombre del archivo  final encriptado
	#	contenido (binary): Contenido de archivo a encriptar
	#
	##

	def saveDecryptedFile(self, archivo, contenido):

		file= archivo
		with open(file, 'wb') as filetowrite:
			filetowrite.write(self.rsa_private_key.encrypt(contenido))
			
	######################################################################################
	#
	# Devuelve un timestamp, usado para crear los nombres de archivo encriptados
	#
	##	
	
	def getTimeStamp(self):
		time.sleep(1)
		ts = calendar.timegm(time.gmtime())
		return ts

	######################################################################################
	#
	# Devuelve la fecha y hora presente
	#
	##	
	
	def getCurrentDateTime(self):
		now = datetime.now()
		return now.strftime("%d/%m%Y %H:%M:%S")
	
	######################################################################################
	#
	# Devuelve la ruta al directorio y el nombre de un archivo dado
	#
	# Args:
	#	pathfile (str): El path del archivo
	##
	
	def getFilenameAndPath(self, pathfile):
		basepath = os.path.dirname(os.path.abspath(pathfile))
		filename = os.path.basename(pathfile)
		
		return basepath, filename
	
	######################################################################################
	#
	# Comprueba si un archivo es parte de un batch
	#
	# Args:
	#	filename (str): El nombre de un archivo
	##
	
	def isBatchFile(self, filename):
		if filename.startswith("TCBATCH"):
			return True

	######################################################################################
	#
	# Extrae los datos referenciales de un archivo batch y devuelve su timestamp, orden,
	# y datos codificados
	#
	# Args:
	#	filename (str): El nombre de un archivo
	##
	
	def extractBatchFile(self, filename):
		filename = filename[7:]
		filename = filename[:-6]
		
		return filename.split("-")	
	
	######################################################################################
	#
	# Devuelve todos los datos codificados de un archivo atravesando sus diferentes
	# archivos batch. La salida que se obtiene se le puede pasar a decryptName(code)
	#
	# Args:
	#	path (str): Ruta del archivo
	#	timestamp (str): Su identificador timestamp
	##		
	
	def readNameFromBatchFiles(self, path, timestamp):
		encoded_name = ""
		for folder, subs, files in os.walk(path):
			with open(os.path.join('logs/python-outfile.txt'), 'w') as dest:
				for filename in sorted(files):
					#kk
					if(folder + "/" + filename != folder + "/" + 'python-outfile.txt'):
						if os.path.splitext(folder + "/" + filename)[1] != ".crypt":
							break
						bfile = self.extractBatchFile(filename)
						if bfile[0] == timestamp:
							encoded_name += bfile[2]
							
		encoded_name = encoded_name.encode("utf-8")
		return base64.b16decode(encoded_name)

	######################################################################################
	#
	# Prepara los archivos batch para ser desencriptados
	#
	# Args:
	#	path (str): Ruta del archivo
	#	timestamp (str): Su identificador timestamp
	##
	
	def prepareBatchFilesDecrypt(self, path, timestamps):
		
		for f in timestamps:
			for x in timestamps[f]['files']:
				path_parts = self.getFilenameAndPath(x)
				bfile = self.extractBatchFile(path_parts[1])
				timestamps[f]['code'] += bfile[2]
		
			
		for i, f in enumerate(timestamps):
				
			encoded_name = timestamps[f]['code'].encode("utf-8")
			decoded_name = base64.b16decode(encoded_name)
			timestamps[f]['original_name'] = self.decryptFileName(decoded_name)
	
		for f in timestamps:
			self.removeBatchFiles(path, timestamps[f]['original_name'], f)

	######################################################################################
	#
	# Renombra el archivo batch principal con su corresponiente nombre desencriptado y 
	# elimina los inncecesarios
	#
	# Args:
	#	path (str): Ruta del archivo
	#	original_name (str): El nombre original del archivo
	#	timestamp (str): El identificador timestamp
	##
					
	def removeBatchFiles(self, path, original_name, timestamp):
		for folder, subs, files in os.walk(path):
			with open(os.path.join('logs/python-outfile.txt'), 'w') as dest:
				for filename in sorted(files):
					#kk
					if(folder + "/" + filename != folder + "/" + 'python-outfile.txt'):
						if os.path.splitext(folder + "/" + filename)[1] != ".crypt":
							break
						bfile = self.extractBatchFile(filename)
						if bfile[0] == timestamp:
							if bfile[1] == "0":
								os.rename(folder + "/" + filename, folder + "/" + original_name + ".crypt")
								continue
							os.remove(folder + "/" + filename)
							
	######################################################################################
	#
	# Save actions log
	#
	# Args:
	#	dest (str): Log type (keys, encrypt, decrypt)
	#	data (str): Data log
	##
					
	def saveLog(self, dest, data):
		
		datetime_now = self.getCurrentDateTime()
		
		if dest == 'keys':
			log_file = 'logs/tekrypto-keys.log'
			try:
				with open(log_file, 'a') as log:
					log.write(datetime_now + "- Generated: " + str(data) + '\n')
			except Exception as Error:
				print(Error)
		
		if dest == 'encrypt':
			log_file = 'logs/tekrypto-encrypt.log'
			try:
				with open(log_file, 'a') as log:
					log.write(datetime_now + "- Encrypted: " + str(data) + '\n')
			except Exception as Error:
				print(Error)

	def ftp(self, directorio):
		return TeFTP(directorio)


def get_args():
	parser = argparse.ArgumentParser()
	parser.add_argument('--action', type=str, help='Action to execute', choices=['generate_keys', 'encrypt', 'decrypt'])
	return parser.parse_args()

if __name__ == '__main__':

	# Print TeKrypto Banner
	banner  = base64.b64decode(get_banner('1.0.3')).decode()
	print(Colorize.YELLOW + Colorize.BOLD + "\n\n" + banner + Colorize.END)

	# Create TeKrypto object
	Crypto = TeKrypto()

	#Print mode and environment info
	print(Colorize.GREEN + "TeKrypto is configured in " + Colorize.END + Colorize.BOLD + Crypto.mode + Colorize.END + Colorize.GREEN  + " mode ->" + Colorize.END)
	print(Colorize.GREEN + "Running in a " + Colorize.END + Colorize.BOLD + Crypto.computer['os'] + " " + Crypto.computer['release'] + Colorize.END + Colorize.GREEN  + " machine ->" + Colorize.END)
	print("")

	# Read args
	args = get_args()

	if Crypto.mode == "Test":

		"""Run test here"""
		#Crypto.useKey("public.pem", "public")
		
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
				Crypto.generateKeys(private_name, public_name, 4096)

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
				Crypto.useKey(key, 'public')
				
				print(Colorize.YELLOW + "Encrypting, wait -->" + Colorize.END)
				
				if type == "f":
					# Encriptar un archivo
					Crypto.encryptFile(encrypt_path, prsv)

				if type == "d":
					# Encriptar un directorio
					Crypto.encryptDirectory(encrypt_path, prsv)

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
				Crypto.useKey(key, 'private')
				
				print(Colorize.YELLOW + "Decrypting, wait -->" + Colorize.END)		
				
				if type == "f":
					# Desencriptar un archivo
					Crypto.decryptFile(decrypt_path, prsv)

				if type == "d":
					# Desencriptar un directorio
					Crypto.decryptDirectory(decrypt_path, prsv)
