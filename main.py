import socket as s
import sys

import nacl.secret
import nacl.utils
import nacl.pwhash
from nacl.signing import VerifyKey
from nacl.pwhash.argon2i import kdf
from nacl.signing import SigningKey

def sign(datos):
    print("Preparando para firmar el archivo:")
    # Generate a new random signing key
    signing_key = SigningKey.generate()

    # Sign a message with the signing key
    signed = signing_key.sign(datos)

    # Obtain the verify key for a given signing key
    verify_key = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    verify_key_bytes = verify_key.encode()
    print("El archivo se ha firmado con exito!")
    return verify_key_bytes,signed.signature,datos

def verify(keybytes,data,signature):
    try:
        verify_key = VerifyKey(keybytes)
        print('Probando firma del archivo:')
        try:
            verify_key.verify(data,signature)
        finally:
            print("Se ha comprobado la firma del archivo, es valida!")
        return
    except:
        print("Firma del archivo no coincide, es una falsificación")

def use_argon2i(data):
    print("Encriptando con argon 2i y guardando el archivo...")
    kdf = nacl.pwhash.argon2i.kdf
    salt_size = nacl.pwhash.argon2i.SALTBYTES
    salt = nacl.utils.random(salt_size)
    key = kdf(nacl.secret.SecretBox.KEY_SIZE, 'practica'.encode("utf-8"), salt)
    box = nacl.secret.SecretBox(key)
    encrypted = box.encrypt(data)
    print("Encriptado y creacion del archivo con exito!")
    return (encrypted,box)

def registrar_acceso(mensaje,user,accesos):
    accesos.write(user + mensaje + "\n")

def ver_accesos():
    f = open("accesos.txt", "r")
    print(f.read())
    return

def save_argon2i(data):
    f = open("Archivo_con_argon.txt", "wb")
    f.write(data)
    f.close()

def decrypt_argon2i(box,encrypted_data):
    print("desencriptando y guardando archivo original: ")
    print(box.decrypt(encrypted_data))
    f = open("Archivo_descifrado_de_argonn.txt", "wb")
    f.write(box.decrypt(encrypted_data))
    f.close()

if __name__ == '__main__':
    accesos = open("accesos.txt", "a")
    print("Inicializando el servidor en la dirección 127.10.10.10, puerto 3000")
    server = s.socket(s.AF_INET, s.SOCK_STREAM)
    server.bind(("127.10.10.10", 3000))
    server.listen()
    conexion,info = server.accept()
    user_flag = False
    datos = conexion.recv(4096).decode()
    print(datos)
    sent_user, sent_pass = datos.split(' ')
    #size = int(size)

    print(f'Se ha recibido: {sent_user} con un password: {sent_pass}')
    with open(r'C:\Users\CAQUIRAR_MX\PycharmProjects\Random_number_SERVER\users.csv', "r") as file:
        for i in file.readlines():
            user:str
            password:str
            user, password = i.strip().split(',')
            print(f'comparacion para log_in  sent user: {sent_user} && {user}, sent password: {sent_pass} && {password}')
            if((user.upper() == sent_user.upper()) and (password.upper() == sent_pass.upper())):
                user_flag = True
                conexion.sendall(b"logeado_con_exito")
                print(f"Hola {user}")
                registrar_acceso(" ha iniciado sesion",user,accesos)
                break

    if (user_flag == False):
        registrar_acceso(" intento conectarse sin exito", sent_user, accesos)
        conexion.close()
    else:
        save = open(r"C:\Users\CAQUIRAR_MX\PycharmProjects\Random_number_SERVER\archivo_a_escribir.txt", "wb")
        print(f'Se ha establecido una conexión en la direccion: {info}')
        datos_nuevos = b''
        datos_completos = b''
        while True:
            datos_nuevos = conexion.recv(4096)
            datos_completos += datos_nuevos
            if(datos_nuevos):
                print(f'Se ha recibido: {datos_nuevos}')
            else:
                break
        print(datos_completos)
        conexion.close()
        accesos.close()
        accesos = open("accesos.txt", "a")
        cliente_keybytes,cliente_signature,archivo_firmado = sign(datos_completos)
        verify(cliente_keybytes,datos_completos,cliente_signature)
        archivo_con_argon,box = use_argon2i(archivo_firmado)
        save_argon2i(archivo_con_argon)
        decrypt_argon2i(box,archivo_con_argon)
        print("Bitacora de Accesos completa:")
        ver_accesos()

