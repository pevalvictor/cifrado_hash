from flask import Flask, render_template, request, send_file, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
import os
from utils.crypto_layers import cifrar_texto, descifrar_texto

app = Flask(__name__)
app.secret_key = 'clave_segura_flask'
app.config['UPLOAD_FOLDER'] = 'uploads'

@app.route('/', methods=['GET', 'POST'])
def index():
    texto_original = ''
    texto_resultado = ''
    clave = ''
    accion = 'cifrar'

    if request.method == 'POST':
        clave = request.form.get('clave', '')
        accion = request.form.get('accion', 'cifrar')
        texto_original = request.form.get('texto', '')
        archivo = request.files.get('archivo', None)

        if not clave:
            flash('⚠️ Debes ingresar una clave.', 'danger')
            return redirect(url_for('index'))

        if archivo and archivo.filename.endswith('.txt'):
            path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(archivo.filename))
            archivo.save(path)
            with open(path, 'r', encoding='utf-8') as f:
                texto_original = f.read()

        if not texto_original.strip():
            flash('⚠️ El campo de texto está vacío.', 'warning')
            return redirect(url_for('index'))

        # Para el procesamiento y mensaje de estado
        if accion == 'cifrar':
            texto_resultado = cifrar_texto(texto_original, clave)
            if not texto_resultado.startswith("❌"):
                flash('✅ Cifrado exitoso.', 'success')
            else:
                flash(texto_resultado, 'danger')
        else:
            texto_resultado = descifrar_texto(texto_original, clave)
            if not texto_resultado.startswith("❌"):
                flash('✅ Descifrado exitoso.', 'success')
            else:
                flash(texto_resultado, 'danger')

        session['resultado'] = texto_resultado

    return render_template('index.html',
                           texto_original=texto_original,
                           resultado=session.get('resultado', ''),
                           clave=clave,
                           accion=accion)

@app.route('/descargar', methods=['POST'])
def descargar():
    contenido = session.get('resultado', '')
    nombre = request.form.get('nombre_archivo', 'resultado.txt')

    if not nombre.endswith('.txt'):
        nombre += '.txt'

    path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(nombre))

    with open(path, 'w', encoding='utf-8') as f:
        f.write(contenido)

    return send_file(path, as_attachment=True)

if __name__ == '__main__':
   
   app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

   # lapp.run(debug=True)
 
