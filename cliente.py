import nacl.utils
import socket as s
import os
import tkinter as tk
from tkinter import filedialog
import sys

if __name__ == '__main__':
  root = tk.Tk()
  root.withdraw()
  print("Nuevo cliente, preparado para conectarse a la 127.10.10.10 en el puerto 3000")
  size = os.path.getsize(r"C:\Users\CAQUIRAR_MX\PycharmProjects\Random_number_SERVER\archivo_a_enviar.txt")
  filename = r"C:\Users\CAQUIRAR_MX\PycharmProjects\Random_number_SERVER\archivo_a_enviar.txt"
  cliente = s.socket(s.AF_INET, s.SOCK_STREAM)
  logeado = False
  cliente.connect(("127.10.10.10", 3000))
  while(True):
    user = input("Escriba su usuario: ")
    password = input("Esriba su contraseña: ")
    cliente.send(f'{user} {password}'.encode())
    if(cliente.recv(4096).decode() == 'logeado_con_exito'):
      print(f'Bienvenido {user}')
      break
    else:
      print("Credenciales incorrectas, prueba otra vez reiniciando el programa")
  print("Logeado con exito")
  filename = filedialog.askopenfilename()
  size = os.path.getsize(filename)
  print(f"{filename} {size}")
  with open(filename, "rb") as file:
    read = file.read()

    cliente.sendall(read)