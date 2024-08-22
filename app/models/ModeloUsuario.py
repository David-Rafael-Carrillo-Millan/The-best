from app.models.entities.Usuario import Usuario
from app.models.entities.TipoUsuario import TipoUsuario
class ModeloUsuario():
    
    @classmethod
    def login(self, db, usuario):
        """Iniciar sesion"""
        try:
            cursor = db.connection.cursor()
            sql = f"SELECT * FROM usuario WHERE usuario = '{usuario.usuario}' AND password = '{usuario.password}'"
            cursor.execute(sql)
            data = cursor.fetchone()
            if data:
                usuario_logueado = Usuario(data[0], data[1], None, None, None, None, None, None, None, None)
                return usuario_logueado
            else:
                return None
        except Exception as ex:
            raise Exception(ex)

    @classmethod
    def obtener_por_id(self, db, id):
        """Obtener los datos del usuario por id"""
        try:
            cursor = db.connection.cursor()
            sql = """SELECT USU.id, USU.usuario, USU.correo_electronico, TIP.id, TIP.nombre 
                FROM usuario USU JOIN tipousuario TIP ON USU.tipousuario_id = TIP.id
                WHERE USU.id = {0}""".format(id)
            cursor.execute(sql)
            data = cursor.fetchone()
            tipousuario = TipoUsuario(data[3], data[4])
            usuario_logueado = Usuario(data[0], data[1], None, tipousuario, None, None, None, None, data[2], None)
            return usuario_logueado
        except Exception as ex:
            raise Exception(ex)

    @classmethod
    def registar_usuario(self, db, usuario):
        """"Metodo para que el usuario se registre"""
        try:
            user = usuario.usuario
            password = usuario.password
            tipousuario_id = usuario.tipousuario
            # Atributos agregados
            nombre = usuario.nombre
            apellido_p = usuario.apellido_p
            apellido_m = usuario.apellido_m
            direccion = usuario.direccion
            correo = usuario.correo_electronico
            telefono = usuario.telefono

            cursor = db.connection.cursor()
            sql = """INSERT INTO usuario (usuario, password, tipousuario_id, nombre, apellido_paterno, apellido_materno, direccion, correo_electronico,
                    telefono_usuario)VALUES ('{0}', '{1}' ,{2}, '{3}', '{4}', '{5}', '{6}', '{7}', '{8}')""".format(user, password, tipousuario_id, nombre, 
                    apellido_p, apellido_m, direccion, correo, telefono)
            cursor.execute(sql)
            db.connection.commit()

            return True
        except Exception as ex:
            raise Exception(ex)
            

    @classmethod
    def usuario_existe(self, db, usuario):
        """"Verificar si el usuario existe en la base de datos"""
        try:
            cursor = db.connection.cursor()
            sql = """SELECT usuario FROM usuario"""
            cursor.execute(sql)
            data = cursor.fetchall()
            usuarios_db = [elemento[0] for elemento in data]

            for usuario_db in usuarios_db:
                if usuario.lower() == usuario_db.lower():
                    return True
            return False

        except Exception as ex:
            raise Exception(ex)

    @classmethod
    def correo_existe(self, db, correo):
        """"Verificar si el usuario existe en la base de datos"""
        try:
            cursor = db.connection.cursor()
            sql = """SELECT correo_electronico FROM usuario"""
            cursor.execute(sql)
            data = cursor.fetchall()
            correos_db = [elemento[0] for elemento in data]

            for correo_db in correos_db:
                if correo.lower() == correo_db.lower():
                    return True
            return False
        except Exception as ex:
            raise Exception(ex)
