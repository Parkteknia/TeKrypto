import os  
import sys
import datetime
from ftplib import FTP	

class TeFTP():	
	
	def __init__(self, directorio):

		self.dominio = 'ftp.arteknia.org'
		self.usuario = ''
		self.password = ''
		
		currentDate = datetime.datetime.now()
		self.dir_session = currentDate.strftime("%Y-%m-%d %H:%M:%S")
		self.directorio = directorio
		
		self.ftp = FTP(self.dominio)
		
		try:
			self.ftp.login(self.usuario, self.password)
			print("Connectado por FTP a: " + self.dominio)
		except Exception as Error:
			print("Error conectando FTP, posiblemente las credenciales: ")
			print(Error)

		try:
			self.preparaSession()
			print("Creado directorio para session: " + self.dir_session)
		except Exception as Error:
			print("Error creando directorio de session")
			print(Error)
		
		self.subeArchivos(self.directorio)
			
		self.ftp.quit()
		print("Session FTP cerrada: CIAO!")
		
	def subeArchivos(self, path):
		
		for name in os.listdir(path):
			
			localpath = os.path.join(path, name)
			
			if os.path.isfile(localpath):
				print("STOR", name, localpath)
				self.ftp.storbinary('STOR ' + name, open(localpath,'rb'))
			elif os.path.isdir(localpath):
				print("MKD", name)
				try:
					self.ftp.mkd( name)

				# ignora si el directorio "existe"
				except error_perm as e:
					
					if not e.args[0].startswith('550'): 
						raise

				print("CWD", self.dir_session + '/' + name)
				self.ftp.cwd(name)
				self.subeArchivos(localpath)           
				print("CWD", "..")
				self.ftp.cwd("..")
				
	def listDir(self):
		self.ftp.cwd('/')
		self.ftp.retrlines('LIST')
		
		
	def enter_dir(self, f, path):  
		original_dir = f.pwd()  
		try:  
			f.cwd(path)  
		except:  
			return  
		print(path)  
		names = f.nlst()  
		for name in names:  
			enter_dir(f, path + '/' + name)  
		f.cwd(original_dir)
		
	def preparaSession(self):
		
		self.ftp.mkd(self.dir_session)
		self.ftp.cwd(self.dir_session)
	
	def upload(data):
		with open('image.png', 'r') as d:  
			f.storlines('STOR %s' % 'image.png', d)


	def cdArbol(dirActual):
		if currentDir != "":
			try:
				
				ftp.cwd(dirActual)
			except IOError:
				cdTree("/".join(dirActual.split("/")[:-1]))
				ftp.mkd(dirActual)
				ftp.cwd(dirActual)
			  
	
