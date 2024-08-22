from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
class Usuario(UserMixin):

    def __init__(self, id, usuario, password, tipousuario, nombre, apellido_p, apellido_m, direccion, correo_electronico, telefono):
        self.id = id
        self.usuario = usuario
        self.password = password
        self.tipousuario = tipousuario
        # Atributos agregados
        self.nombre = nombre
        self.apellido_p = apellido_p
        self.apellido_m = apellido_m
        self.direccion = direccion
        self.correo_electronico = correo_electronico
        self.telefono = telefono

    @classmethod
    def verificar_password(self, encriptado, password):
        return check_password_hash(encriptado, password)