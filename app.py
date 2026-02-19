from flask import Flask, render_template, request, redirect, session, url_for, flash
from supabase import create_client, Client
from dotenv import load_dotenv
import os
import random
import string
from datetime import datetime, timedelta, date, time
from utils.email_service import send_email
from itsdangerous import URLSafeTimedSerializer
import uuid

app = Flask(__name__)

app.secret_key = "clave_super_segura"

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


SECURITY_PASSWORD_SALT = "recovery-salt"
serializer = URLSafeTimedSerializer(app.secret_key)


def generar_codigo_ruta():
    letras = ''.join(random.choices(string.ascii_uppercase, k=3))
    numeros = ''.join(random.choices(string.digits, k=4))
    return f"R-{letras}{numeros}"

# -----------------------
# LOGIN
# -----------------------
from werkzeug.security import check_password_hash, generate_password_hash

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        # 🔎 Buscar solo por email y estado
        response = supabase.table("usuarios") \
            .select("*") \
            .eq("email", email) \
            .eq("estado", True) \
            .execute()

        if response.data:

            user = response.data[0]

            stored_password = user["password"]

            login_ok = False

            # 🔐 Si ya está encriptada
            if stored_password.startswith("scrypt:"):
                if check_password_hash(stored_password, password):
                    login_ok = True
            else:
                # 🟡 Usuario viejo con contraseña en texto plano
                if stored_password == password:
                    login_ok = True

                    # Migramos automáticamente a hash
                    new_hash = generate_password_hash(password)

                    supabase.table("usuarios").update({
                        "password": new_hash
                    }).eq("email", email).execute()

            if login_ok:
                # Guardamos temporalmente
                session["pending_user_id"] = user["id"]

                return redirect(url_for("verificar_token"))

               

        return render_template("login.html", error="Credenciales incorrectas")

    return render_template("login.html")


def generar_token_unico():

    while True:
        token = str(random.randint(100000, 999999))

        # Verificar que no exista
        response = supabase.table("usuarios") \
            .select("id") \
            .eq("token_ingreso", token) \
            .execute()

        if not response.data:
            return token

@app.route("/usuarios/generar-token/<int:user_id>")
def generar_token_usuario(user_id):

    response = supabase.table("usuarios") \
        .select("*") \
        .eq("id", user_id) \
        .execute()

    if not response.data:
        flash("Usuario no encontrado.", "error")
        return redirect(url_for("usuarios"))

    user = response.data[0]

    token = generar_token_unico()

    # Guardar token
    supabase.table("usuarios").update({
        "token_ingreso": token
    }).eq("id", user_id).execute()

    # Enviar correo
    asunto = "Token de acceso al sistema"
    mensaje = f"""
    Hola {user['nombres']},

    Tu token de acceso es: {token}

    Usa este código para ingresar al sistema.
    """

    send_email(user["email"], asunto, mensaje)

    flash("Token generado y enviado al correo.", "success")

    return redirect(url_for("usuarios"))


@app.route("/verificar-token", methods=["GET", "POST"])
def verificar_token():

    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":

        token_ingresado = request.form.get("token")

        response = supabase.table("usuarios") \
            .select("*") \
            .eq("id", session["pending_user_id"]) \
            .execute()

        if not response.data:
            return redirect(url_for("login"))

        user = response.data[0]

        if user["token_ingreso"] == token_ingresado:

            # 🔥 Limpiamos token después de usarlo
            supabase.table("usuarios").update({
                "token_ingreso": None
            }).eq("id", user["id"]).execute()

            session.pop("pending_user_id", None)

            session["user_id"] = user["id"]
            session["nombre"] = user["nombres"]
            session["apellido"] = user["apellidos"]
            session["rol"] = user["rol"]

            flash("Acceso autorizado.", "success")
            return redirect(url_for("cambiar_oficina"))

        else:
            flash("Token incorrecto.", "error")
            return redirect(url_for("verificar_token"))


    return render_template("forgot_password/verificar_token.html")



@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':

        documento = request.form.get("documento")

        response = supabase.table("usuarios") \
            .select("email, documento") \
            .eq("documento", documento) \
            .execute()

        if response.data:

            user = response.data[0]
            email = user["email"]

            token = serializer.dumps(email, salt=SECURITY_PASSWORD_SALT)
            reset_url = url_for('reset_password', token=token, _external=True)

            subject = "Recuperación de contraseña"
            body = f"""
            Hola,

            Haz clic en el siguiente enlace para restablecer tu contraseña:

            {reset_url}

            Si no solicitaste esto, ignora el mensaje.
            """

            send_email(email, subject, body)


            flash("Se envió un enlace al correo registrado.", "success")

        else:
            flash("El documento ingresado no existe en nuestra base de datos.", "error")
            return redirect(url_for("forgot_password"))  # 👈 IMPORTANTE

    return render_template('forgot_password/forgot_password.html')



@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):

    try:
        email = serializer.loads(
            token,
            salt=SECURITY_PASSWORD_SALT,
            max_age=3600
        )
    except:
        flash("El enlace ha expirado o es inválido.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == 'POST':

        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Validaciones
        if not password or not confirm_password:
            flash("Todos los campos son obligatorios.", "error")
            return redirect(request.url)

        if len(password) < 6:
            flash("La contraseña debe tener mínimo 6 caracteres.", "error")
            return redirect(request.url)

        if password != confirm_password:
            flash("Las contraseñas no coinciden.", "error")
            return redirect(request.url)

        from werkzeug.security import generate_password_hash
        hashed_password = generate_password_hash(password)

        supabase.table("usuarios").update({
            "password": hashed_password
        }).eq("email", email).execute()

        flash("Contraseña actualizada correctamente.", "success")

    return render_template("forgot_password/reset_password.html")

# -----------------------
# LOGIN APP
# -----------------------

@app.route("/login_app", methods=["GET", "POST"])
def login_app():

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        if not email or not password:
            return render_template(
                "login_app/login_app.html",
                error="Debe ingresar correo y contraseña"
            )

        # 🔎 Buscar solo cobradores activos
        response = supabase.table("usuarios") \
            .select("*") \
            .eq("email", email) \
            .eq("estado", True) \
            .eq("rol", "Cobrador") \
            .execute()

        if not response.data:
            return render_template(
                "login_app/login_app.html",
                error="Usuario no encontrado o no autorizado"
            )

        user = response.data[0]
        stored_password = user["password"]

        login_ok = False

        # 🔐 Si está encriptada
        if stored_password.startswith("scrypt:"):
            if check_password_hash(stored_password, password):
                login_ok = True
        else:
            # 🔄 Migración automática si estaba en texto plano
            if stored_password == password:
                login_ok = True

                new_hash = generate_password_hash(password)

                supabase.table("usuarios").update({
                    "password": new_hash
                }).eq("id", user["id"]).execute()

        if not login_ok:
            return render_template(
                "login_app/login_app.html",
                error="Contraseña incorrecta"
            )

        # 🔐 Login exitoso
        session.clear()
        session["pending_user_id"] = user["id"]   # 👈 IMPORTANTE
        session["login_tipo"] = "app"            # opcional si quieres diferenciar

        return redirect(url_for("verificar_token_app"))


    return render_template("login_app/login_app.html")


@app.route("/verificar-token-app", methods=["GET", "POST"])
def verificar_token_app():

    if "pending_user_id" not in session:
        return redirect(url_for("login_app"))

    if request.method == "POST":

        token_ingresado = request.form.get("token")

        response = supabase.table("usuarios") \
            .select("*") \
            .eq("id", session["pending_user_id"]) \
            .eq("rol", "Cobrador") \
            .execute()

        if not response.data:
            return redirect(url_for("login_app"))

        user = response.data[0]

        if user["token_ingreso"] == token_ingresado:

            # 🔥 limpiar token después de usarlo
            supabase.table("usuarios").update({
                "token_ingreso": None
            }).eq("id", user["id"]).execute()

            # 🔐 Crear sesión REAL
            session.pop("pending_user_id", None)

            session["user_id"] = user["id"]
            session["rol"] = user["rol"].lower()

            # ✅ Nombre
            nombres = user.get("nombres", "")
            apellidos = user.get("apellidos", "")
            email = user.get("email", "")

            session["nombre"] = nombres
            session["nombre_completo"] = f"{nombres} {apellidos}".strip()
            session["email"] = email


            session.permanent = True
            app.permanent_session_lifetime = timedelta(hours=8)


            return redirect(url_for("dashboard_cobrador"))

        else:
            flash("Token incorrecto.", "error")
            return redirect(url_for("verificar_token_app"))

    return render_template("login_app/verificar_token_app.html")


@app.route("/dashboard_cobrador")
def dashboard_cobrador():

    # 1️⃣ Validar sesión
    if "user_id" not in session or session.get("rol") != "cobrador":
        return redirect(url_for("login_app"))

    user_id = int(session["user_id"])

    # 2️⃣ Traer rutas asignadas al usuario
    response = supabase.table("rutas") \
        .select("*") \
        .eq("usuario_id", user_id) \
        .eq("estado", "true") \
        .order("posicion") \
        .execute()

    rutas = response.data if response.data else []

    # 🔥 3️⃣ ASEGURAR RUTA ACTIVA
    if rutas and not session.get("ruta_id"):
        session["ruta_id"] = rutas[0]["id"]

    # 🔥 4️⃣ VALIDAR QUE LA RUTA ACTIVA SIGA EXISTIENDO
    if session.get("ruta_id"):
        ruta_activa_valida = any(r["id"] == session["ruta_id"] for r in rutas)
        if not ruta_activa_valida and rutas:
            session["ruta_id"] = rutas[0]["id"]

    # 5️⃣ Manejar oficinas
    rutas_completas = []
    for ruta in rutas:
        oficina_info = None
        if ruta.get("oficina_id"):
            oficina_resp = supabase.table("oficinas") \
                .select("*") \
                .eq("id", ruta["oficina_id"]) \
                .execute()
            if oficina_resp.data:
                oficina_info = oficina_resp.data[0]

        ruta["oficina"] = oficina_info
        rutas_completas.append(ruta)

    return render_template(
        "cobrador/dashboard.html",
        rutas=rutas_completas,
        ruta_id=session.get("ruta_id")  # 👈 PASARLO AL TEMPLATE
    )



# 🔎 Traer crédito + cliente APP
# 🔎 Traer crédito + cliente APP
@app.route("/credito/<credito_id>")
def detalle_credito(credito_id):

    if "user_id" not in session or session.get("rol") != "cobrador":
        return redirect(url_for("login_app"))

    # 🔎 Traer crédito + cliente con campos necesarios
    credito = supabase.table("creditos") \
        .select("""
            *,
            clientes(
                id,
                nombre,
                identificacion,
                telefono_principal,
                direccion
            )
        """) \
        .eq("id", credito_id) \
        .single() \
        .execute().data

    if not credito:
        return redirect(url_for("dashboard_cobrador"))

    # 🔎 Traer cuotas
    cuotas_db = supabase.table("cuotas") \
        .select("*") \
        .eq("credito_id", credito_id) \
        .order("numero") \
        .execute().data

    total_pagado = 0
    cuotas = []
    proxima_cuota = None

    for c in cuotas_db:

        dias_mora = 0

        # 🔹 Sumar pagadas
        if c["estado"] == "pagado":
            total_pagado += float(c.get("monto_pagado", c["valor"]))

        # 🔹 Detectar mora
        if c["estado"] == "pendiente":
            fecha = date.fromisoformat(c["fecha_pago"])
            if fecha < date.today():
                dias_mora = (date.today() - fecha).days

            # 🔹 Primera cuota pendiente = próxima cuota
            if not proxima_cuota:
                proxima_cuota = c["fecha_pago"]

        cuotas.append({
            "id": c["id"],
            "numero": c["numero"],
            "valor": c["valor"],
            "estado": c["estado"],
            "fecha_pago": c["fecha_pago"],
            "dias_mora": dias_mora
        })

    # 🔹 Calcular saldo
    saldo = float(credito["valor_total"]) - total_pagado

    return render_template(
        "cobrador/detalle_credito.html",
        credito=credito,
        cuotas=cuotas,
        saldo=saldo,
        total_pagado=total_pagado,
        proxima_cuota=proxima_cuota
    )

@app.route("/registrar_pago", methods=["POST"])
def registrar_pago():

    cuota_id = request.form.get("cuota_id")
    monto_adicional = float(request.form.get("monto_adicional", 0))

    if not cuota_id:
        return redirect(request.referrer)

    # 🔎 Traer cuota
    cuota_resp = supabase.table("cuotas") \
        .select("*") \
        .eq("id", cuota_id) \
        .single() \
        .execute()

    if not cuota_resp.data:
        return redirect(request.referrer)

    cuota = cuota_resp.data

    # 🔹 Calcular total pagado
    valor_cuota = float(cuota["valor"])
    total_pagado = valor_cuota + monto_adicional

    # 🔥 Actualizar cuota como pagada
    supabase.table("cuotas").update({
        "estado": "pagado",
        "monto_pagado": total_pagado,
        "fecha_pago_real": datetime.now().isoformat()
    }).eq("id", cuota_id).execute()

    credito_id = cuota["credito_id"]

    # 🔥 Registrar en tabla pagos
    pago_resp = supabase.table("pagos").insert({
        "cuota_id": cuota_id,
        "credito_id": credito_id,
        "monto": total_pagado,
        "fecha": datetime.now().isoformat(),
        "cobrador_id": session["user_id"]
    }).execute()

    pago_id = pago_resp.data[0]["id"]

    # 🔎 Verificar si quedan cuotas pendientes
    cuotas_pendientes = supabase.table("cuotas") \
        .select("id") \
        .eq("credito_id", credito_id) \
        .eq("estado", "pendiente") \
        .execute()

    if not cuotas_pendientes.data:
        # 🔥 Si no quedan pendientes → crédito pagado
        supabase.table("creditos").update({
            "estado": "pagado"
        }).eq("id", credito_id).execute()

    return redirect(url_for("recibo_pago", pago_id=pago_id))


@app.route("/recibo/<pago_id>")
def recibo_pago(pago_id):

    pago = supabase.table("pagos") \
        .select("""
            *,
            cuotas(
                numero,
                credito_id,
                creditos(
                    id,
                    valor_total,
                    rutas(
                        codigo,
                        nombre
                    ),
                    clientes(
                        nombre
                    )
                )
            )
        """) \
        .eq("id", pago_id) \
        .single() \
        .execute().data

    # Calcular saldo restante
    credito_id = pago["cuotas"]["credito_id"]

    cuotas = supabase.table("cuotas") \
        .select("*") \
        .eq("credito_id", credito_id) \
        .execute().data

    total_pagado = sum(float(c.get("monto_pagado", 0)) for c in cuotas if c["estado"] == "pagado")
    saldo_restante = float(pago["cuotas"]["creditos"]["valor_total"]) - total_pagado

    return render_template(
        "cobrador/recibo_pago.html",
        pago=pago,
        saldo_restante=saldo_restante
    )




# =============================
# NUEVA VENTA COBRADOR (CONTROL FLUJO)
# =============================
@app.route("/nueva_venta_cobrador")
def nueva_venta_cobrador():

    # 🔐 Validar sesión
    if "user_id" not in session or session.get("rol") != "cobrador":
        return redirect(url_for("login_app"))

    user_id = int(session["user_id"])

    # 🔹 Traer rutas del cobrador (igual que dashboard)
    response = supabase.table("rutas") \
        .select("*") \
        .eq("usuario_id", user_id) \
        .eq("estado", "true") \
        .order("posicion") \
        .execute()

    rutas = response.data if response.data else []

    # 🔹 Ruta actual
    ruta_actual = session.get("ruta_id")

    # 🔹 Si no hay ruta en sesión, usar la primera
    if not ruta_actual and rutas:
        ruta_actual = rutas[0]["id"]
        session["ruta_id"] = ruta_actual

    return render_template(
        "cobrador/nueva_venta_cobrador.html",
        rutas=rutas,
        ruta_actual=ruta_actual
    )

@app.route("/guardar_venta_cobrador", methods=["POST"])
def guardar_venta_cobrador():

    if "user_id" not in session:
        return redirect(url_for("login_app"))

    # 🔹 Traer rutas del cobrador (para re-render sin romper diseño)
    rutas_resp = supabase.table("rutas") \
        .select("*") \
        .eq("usuario_id", session["user_id"]) \
        .eq("estado", "true") \
        .order("posicion") \
        .execute()

    rutas = rutas_resp.data if rutas_resp.data else []

    ruta_id = request.form.get("ruta_id")
    session["ruta_id"] = ruta_id

    if not ruta_id:
        flash("No hay ruta activa seleccionada", "danger")
        return redirect(url_for("dashboard_cobrador"))

    # ==========================
    # VALIDAR CAMPOS NUMÉRICOS
    # ==========================

    try:
        posicion = int(request.form.get("posicion", "").strip())
        if posicion <= 0:
            raise ValueError
    except:
        flash("Debe ingresar una posición válida", "danger")
        return render_template(
            "cobrador/nueva_venta_cobrador.html",
            rutas=rutas,
            ruta_actual=ruta_id,
            form_data=request.form
        )

    try:
        valor_venta_raw = request.form.get("valor_venta", "").strip()
        tasa_raw = request.form.get("tasa", "").strip()
        cuotas_raw = request.form.get("cuotas", "").strip()

        # 🔹 Limpiar formato colombiano
        valor_venta = float(valor_venta_raw.replace(".", "").replace(",", "."))
        tasa = float(tasa_raw.replace(",", "."))
        cuotas = int(cuotas_raw)

        if valor_venta <= 0 or cuotas <= 0:
            raise ValueError

    except Exception as e:
        print("ERROR NUMERICO:", e)  # Para depurar
        flash("Datos numéricos inválidos", "danger")
        return render_template(
            "cobrador/nueva_venta_cobrador.html",
            rutas=rutas,
            ruta_actual=ruta_id,
            form_data=request.form
        )

    identificacion = request.form.get("identificacion")
    nombre = request.form.get("nombre")
    direccion = request.form.get("direccion")
    telefono = request.form.get("telefono")
    fecha_inicio = request.form.get("fecha_inicio")
    tipo_prestamo = request.form.get("tipo_prestamo")

    # ==========================
    # VALIDAR POSICIÓN DUPLICADA
    # ==========================

    posicion_existente = supabase.table("creditos") \
        .select("id") \
        .eq("ruta_id", ruta_id) \
        .eq("posicion", posicion) \
        .eq("estado", "activo") \
        .limit(1) \
        .execute()

    if posicion_existente.data:
        flash("Ya existe un cliente activo en esa posición", "danger")
        return render_template(
            "cobrador/nueva_venta_cobrador.html",
            rutas=rutas,
            ruta_actual=ruta_id,
            form_data=request.form
        )

    # ==========================
    # 1️⃣ BUSCAR O CREAR CLIENTE
    # ==========================

    cliente_resp = supabase.table("clientes") \
        .select("*") \
        .eq("identificacion", identificacion) \
        .limit(1) \
        .execute()

    if cliente_resp.data:
        cliente_id = cliente_resp.data[0]["id"]
    else:
        nuevo_cliente = supabase.table("clientes").insert({
            "identificacion": identificacion,
            "nombre": nombre,
            "direccion": direccion,
            "telefono_principal": telefono
        }).execute()

        if not nuevo_cliente.data:
            flash("Error creando cliente", "danger")
            return render_template(
                "cobrador/nueva_venta_cobrador.html",
                rutas=rutas,
                ruta_actual=ruta_id,
                form_data=request.form
            )

        cliente_id = nuevo_cliente.data[0]["id"]

    # ==========================
    # 2️⃣ SUBIR FOTOS
    # ==========================

    import uuid

    foto_cedula = request.files.get("foto_cedula")
    foto_negocio = request.files.get("foto_negocio")

    if foto_cedula:
        try:
            cedula_path = f"{cliente_id}_{uuid.uuid4()}_cedula.jpg"
            supabase.storage.from_("clientes").upload(
                cedula_path,
                foto_cedula.read(),
                {"content-type": foto_cedula.content_type}
            )
        except:
            pass

    if foto_negocio:
        try:
            negocio_path = f"{cliente_id}_{uuid.uuid4()}_negocio.jpg"
            supabase.storage.from_("clientes").upload(
                negocio_path,
                foto_negocio.read(),
                {"content-type": foto_negocio.content_type}
            )
        except:
            pass

    # ==========================
    # 3️⃣ CREAR CRÉDITO
    # ==========================

    valor_total = valor_venta + (valor_venta * tasa / 100)
    valor_cuota = valor_total / cuotas

    credito_resp = supabase.table("creditos").insert({
        "cliente_id": cliente_id,
        "ruta_id": ruta_id,
        "posicion": posicion,
        "tipo_prestamo": tipo_prestamo,
        "valor_venta": valor_venta,
        "tasa": tasa,
        "valor_total": valor_total,
        "cantidad_cuotas": cuotas,
        "valor_cuota": valor_cuota,
        "fecha_inicio": fecha_inicio,
        "estado": "activo"
    }).execute()

    if not credito_resp.data:
        flash("Error al registrar el crédito", "danger")
        return render_template(
            "cobrador/nueva_venta_cobrador.html",
            rutas=rutas,
            ruta_actual=ruta_id,
            form_data=request.form
        )

    credito_id = credito_resp.data[0]["id"]

    # ==========================
    # 4️⃣ CREAR CUOTAS
    # ==========================


    fecha = datetime.strptime(fecha_inicio, "%Y-%m-%d")

    for i in range(cuotas):
        supabase.table("cuotas").insert({
            "credito_id": credito_id,
            "numero": i + 1,
            "valor": valor_cuota,
            "estado": "pendiente",
            "fecha_pago": (fecha + timedelta(days=i)).date().isoformat()
        }).execute()

    flash("Venta registrada correctamente", "success")

    return redirect(url_for("ver_ruta", ruta_id=ruta_id))


# listar todas las ventas en el motudlo de cobrador

@app.route("/todas_las_ventas/<ruta_id>")
def todas_las_ventas(ruta_id):

    if "user_id" not in session or session.get("rol") != "cobrador":
        return redirect(url_for("login_app"))

    hoy = date.today().isoformat()

    # Traer créditos activos con info cliente
    response = supabase.table("creditos") \
        .select("""
            id,
            posicion,
            valor_cuota,
            valor_total,
            tipo_prestamo,
            clientes(
                nombre,
                identificacion,
                telefono_principal
            )
        """) \
        .eq("ruta_id", ruta_id) \
        .eq("estado", "activo") \
        .order("posicion") \
        .execute()

    creditos = response.data if response.data else []
    lista = []
    for c in creditos:

        cuotas = supabase.table("cuotas") \
            .select("estado, valor, fecha_pago") \
            .eq("credito_id", c["id"]) \
            .order("fecha_pago") \
            .execute().data

        pago_hoy = None   # 🔥 importante
        valor_hoy = 0
        proxima_cuota = None

        for cuota in cuotas:

            # 🔹 Detectar cuota de hoy
            if cuota["fecha_pago"] == hoy:
                valor_hoy = cuota["valor"]

                if cuota["estado"] == "pagado":
                    pago_hoy = True
                else:
                    pago_hoy = False

            # 🔹 Detectar próxima pendiente
            if cuota["estado"] == "pendiente" and not proxima_cuota:
                proxima_cuota = cuota["fecha_pago"]

        # 🔥 Si no tiene cuota hoy, no debe pagar hoy
        if pago_hoy is None:
            pago_hoy = True

        lista.append({
            "id": c["id"],
            "posicion": c["posicion"],
            "cliente": c["clientes"]["nombre"],
            "telefono": c["clientes"]["telefono_principal"],
            "valor_total": "{:,.0f}".format(c["valor_total"]),
            "valor_hoy": "{:,.0f}".format(valor_hoy),
            "proxima_cuota": proxima_cuota,
            "pago_hoy": pago_hoy
        })



    return render_template(
        "cobrador/todas_las_ventas.html",
        creditos=lista,
        ruta_id=ruta_id
    )




    # =============================
    # CAJA COBRADOR
    # =============================
@app.route("/caja_cobrador")
def caja_cobrador():

    if "user_id" not in session or session.get("rol") != "cobrador":
        return redirect(url_for("login_app"))

    ruta_id = session.get("ruta_id")

    if not ruta_id:
        return redirect(url_for("dashboard_cobrador"))

    hoy = date.today()
    hoy_iso = hoy.isoformat()

    # =====================================
    # 1️⃣ TRAER SALDO ANTERIOR (último cierre)
    # =====================================

    cierre_resp = supabase.table("caja_diaria") \
        .select("*") \
        .eq("ruta_id", ruta_id) \
        .lt("fecha", hoy_iso) \
        .order("fecha", desc=True) \
        .limit(1) \
        .execute()

    if cierre_resp.data:
        saldo_anterior = float(cierre_resp.data[0]["saldo_final"])
    else:
        saldo_anterior = 0

    # =====================================
    # 2️⃣ PRÉSTAMOS REALIZADOS HOY
    # =====================================

    prestamos_resp = supabase.table("creditos") \
        .select("""
            id,
            valor_venta,
            created_at,
            clientes(nombre)
        """) \
        .eq("ruta_id", ruta_id) \
        .gte("created_at", hoy_iso) \
        .execute()

    prestamos_db = prestamos_resp.data or []

    total_prestamos = 0
    lista_prestamos = []

    for p in prestamos_db:
        valor = float(p["valor_venta"] or 0)
        total_prestamos += valor

        lista_prestamos.append({
            "cliente": p["clientes"]["nombre"],
            "valor": valor
        })

    # =====================================
    # 3️⃣ COBROS REALIZADOS HOY
    # =====================================

    inicio_dia = datetime.combine(hoy, time.min)
    fin_dia = datetime.combine(hoy, time.max)

    pagos_resp = supabase.table("pagos") \
        .select("""
            monto,
            fecha,
            creditos(
                ruta_id,
                clientes(nombre)
            )
        """) \
        .gte("fecha", inicio_dia.isoformat()) \
        .lte("fecha", fin_dia.isoformat()) \
        .execute()

    pagos_db = pagos_resp.data or []

    total_cobros = 0
    lista_cobros = []

    for pago in pagos_db:

        if pago["creditos"] and int(pago["creditos"]["ruta_id"]) == int(ruta_id):

            monto = float(pago["monto"] or 0)
            total_cobros += monto

            lista_cobros.append({
                "cliente": pago["creditos"]["clientes"]["nombre"],
                "valor": monto
            })

    # =====================================
    # 4️⃣ GASTOS DEL DÍA (si existen)
    # =====================================

    gastos_resp = supabase.table("gastos") \
        .select("monto") \
        .eq("ruta_id", ruta_id) \
        .gte("fecha", hoy_iso) \
        .execute()

    gastos_db = gastos_resp.data or []

    total_gastos = sum(float(g["monto"]) for g in gastos_db)

    # =====================================
    # 5️⃣ CALCULAR SALDO ACTUAL
    # =====================================

    saldo_actual = saldo_anterior + total_cobros - total_prestamos - total_gastos

    # =====================================
    # 6️⃣ RENDER
    # =====================================

    return render_template(
        "cobrador/caja.html",
        saldo_actual=saldo_actual,
        saldo_anterior=saldo_anterior,
        total_prestamos=total_prestamos,
        total_cobros=total_cobros,
        total_gastos=total_gastos,
        prestamos=lista_prestamos,
        cobros=lista_cobros
    )

@app.route("/cerrar_dia", methods=["POST"])
def cerrar_dia():

    ruta_id = session.get("ruta_id")
    hoy = date.today().isoformat()

    # calcular saldo actual otra vez aquí

    supabase.table("caja_diaria").insert({
        "ruta_id": ruta_id,
        "fecha": hoy,
        "saldo_final": saldo_actual
    }).execute()

    flash("Caja cerrada correctamente", "success")
    return redirect(url_for("caja_cobrador"))


# Traer todos los clientes de la eruta para el modulo CLIENTES

@app.route("/clientes_ruta/<ruta_id>")
def clientes_ruta(ruta_id):

    if "user_id" not in session or session.get("rol") != "cobrador":
        return redirect(url_for("login_app"))

    # Traer todos los créditos de la ruta (activos o no)
    creditos_resp = supabase.table("creditos") \
        .select("""
            cliente_id,
            estado,
            clientes(
                id,
                nombre,
                identificacion,
                telefono_principal,
                direccion
            )
        """) \
        .eq("ruta_id", ruta_id) \
        .execute()

    creditos = creditos_resp.data or []

    clientes_dict = {}

    for c in creditos:
        cliente = c["clientes"]
        cliente_id = cliente["id"]

        # Si no existe lo agregamos
        if cliente_id not in clientes_dict:
            clientes_dict[cliente_id] = {
                "id": cliente_id,
                "nombre": cliente["nombre"],
                "identificacion": cliente["identificacion"],
                "telefono": cliente["telefono_principal"],
                "direccion": cliente["direccion"],
                "credito_activo": False
            }

        # Si alguno está activo → marcar
        if c["estado"] == "activo":
            clientes_dict[cliente_id]["credito_activo"] = True

    clientes_lista = list(clientes_dict.values())

    return render_template(
        "cobrador/clientes_ruta.html",
        clientes=clientes_lista,
        ruta_id=ruta_id
    )

@app.route("/detalle_cliente/<cliente_id>/<ruta_id>")
def detalle_cliente(cliente_id, ruta_id):

    if "user_id" not in session or session.get("rol") != "cobrador":
        return redirect(url_for("login_app"))

    # Traer info cliente
    cliente_resp = supabase.table("clientes") \
        .select("*") \
        .eq("id", cliente_id) \
        .single() \
        .execute()

    if not cliente_resp.data:
        return redirect(url_for("clientes_ruta", ruta_id=ruta_id))

    cliente = cliente_resp.data

    # Verificar si tiene crédito activo en esa ruta
    credito_resp = supabase.table("creditos") \
        .select("id") \
        .eq("cliente_id", cliente_id) \
        .eq("ruta_id", ruta_id) \
        .eq("estado", "activo") \
        .limit(1) \
        .execute()

    tiene_credito_activo = bool(credito_resp.data)

    return render_template(
        "cobrador/detalle_cliente.html",
        cliente=cliente,
        ruta_id=ruta_id,
        tiene_credito_activo=tiene_credito_activo
    )


@app.route("/ruta/<ruta_id>")
def ver_ruta(ruta_id):

    # 🔐 1️⃣ Validar sesión
    if "user_id" not in session or session.get("rol") != "cobrador":
        return redirect(url_for("login_app"))

    user_id = int(session["user_id"])

    # 🔎 2️⃣ Validar que la ruta le pertenezca
    ruta_resp = supabase.table("rutas") \
        .select("*") \
        .eq("id", ruta_id) \
        .eq("usuario_id", user_id) \
        .single() \
        .execute()

    if not ruta_resp.data:
        return redirect(url_for("dashboard_cobrador"))

    ruta = ruta_resp.data

    # 🔥 3️⃣ Guardar ruta activa en sesión
    session["ruta_id"] = ruta_id

    # 🔎 4️⃣ Traer créditos activos con info cliente
    response = supabase.table("creditos") \
        .select("""
            id,
            cliente_id,
            posicion,
            valor_total,
            tipo_prestamo,
            created_at,
            clientes(
                nombre,
                identificacion,
                telefono_principal,
                direccion
            )
        """) \
        .eq("ruta_id", ruta_id) \
        .eq("estado", "activo") \
        .order("posicion") \
        .execute()

    creditos = response.data if response.data else []
    lista_creditos = []

    # 🔎 5️⃣ Procesar cada crédito
    for c in creditos:

        cuotas = supabase.table("cuotas") \
            .select("valor, estado, fecha_pago") \
            .eq("credito_id", c["id"]) \
            .order("numero") \
            .execute().data

        total_pagado = 0
        dias_mora = 0
        proxima_cuota = None

        for cuota in cuotas:

            # 🔹 Sumar pagadas
            if cuota["estado"] == "pagado":
                total_pagado += float(cuota["valor"])

            # 🔹 Detectar mora y próxima cuota
            if cuota["estado"] == "pendiente":

                fecha_pago = date.fromisoformat(cuota["fecha_pago"])

                if fecha_pago < date.today():
                    dias_mora += (date.today() - fecha_pago).days

                if not proxima_cuota:
                    proxima_cuota = cuota["fecha_pago"]

        saldo = float(c["valor_total"]) - total_pagado

        lista_creditos.append({
            "id": c["id"],
            "posicion": c["posicion"],
            "cliente": c["clientes"]["nombre"],
            "identificacion": c["clientes"]["identificacion"],
            "telefono": c["clientes"]["telefono_principal"],
            "direccion": c["clientes"]["direccion"],
            "tipo_prestamo": c["tipo_prestamo"],
            "saldo": "{:,.0f}".format(saldo),
            "dias_mora": dias_mora,
            "proxima_cuota": proxima_cuota,
            "codigo": c["id"][:6]
        })

    # 🔥 6️⃣ Enviar ruta_id al template (clave para el layout)
    return render_template(
        "cobrador/ventas_ruta.html",
        ruta=ruta,
        creditos=lista_creditos,
        ruta_id=ruta_id
    )


@app.route("/oficinas/crear", methods=["POST"])
def crear_oficina():

    nombre = request.form.get("nombre")
    pais = request.form.get("pais")
    codigo = request.form.get("codigo")

    if not nombre or not pais:
        flash("Nombre y país son obligatorios.", "danger")
        return redirect("/oficina/change")

    supabase.table("oficinas").insert({
        "nombre": nombre,
        "pais": pais,
        "codigo": codigo,
        "rutas_activas": 0
    }).execute()

    flash("Oficina creada correctamente.", "success")
    return redirect("/oficina/change")

# -----------------------
# SELECCIONAR OFICINA
# -----------------------
@app.route("/oficina/change")
def cambiar_oficina():

    if "user_id" not in session:
        return redirect(url_for("login"))

    oficinas_resp = supabase.table("oficinas") \
        .select("id,nombre,pais") \
        .order("created_at", desc=True) \
        .execute()

    oficinas = oficinas_resp.data

    for oficina in oficinas:

        rutas_resp = supabase.table("rutas") \
            .select("id,estado") \
            .eq("oficina_id", str(oficina["id"])) \
            .execute()

        rutas = rutas_resp.data or []

        oficina["rutas_activas"] = len([
            r for r in rutas if r["estado"] == "true"
        ])

    return render_template("oficinas.html", oficinas=oficinas)


# -----------------------
# SELECCIONAR OFICINA (GUARDAR EN SESSION)
# -----------------------
@app.route("/oficina/select/<oficina_id>")
def seleccionar_oficina(oficina_id):

    if "user_id" not in session:
        return redirect(url_for("login"))

    response = supabase.table("oficinas") \
        .select("*") \
        .eq("id", oficina_id) \
        .single() \
        .execute()

    if not response.data:
        flash("Oficina no encontrada", "danger")
        return redirect(url_for("dashboard"))

    oficina = response.data

    session["oficina_id"] = oficina["id"]   # UUID string
    session["oficina_nombre"] = oficina["nombre"]
    session["oficina_pais"] = oficina["pais"]

    return redirect(url_for("dashboard"))

# -----------------------
# LISTAR EL REPORTE DE USUARIOS
# -----------------------
@app.route("/usuarios")
def usuarios():

    response = supabase.table("usuarios") \
        .select("*") \
        .order("fecha_registro", desc=True) \
        .execute()

    usuarios = response.data

    return render_template("users.html", usuarios=usuarios)

# -----------------------
# CREAR UN NUEVO USUARIO EN EL SISTEMA
# -----------------------
@app.route("/usuarios/crear", methods=["POST"])
def crear_usuario():

    nombres = request.form["nombres"]
    apellidos = request.form["apellidos"]
    documento = request.form["documento"]
    email = request.form["email"]
    rol = request.form["rol"]
    password = request.form["password"]

    # Validar email
    existe_email = supabase.table("usuarios") \
        .select("id") \
        .eq("email", email) \
        .execute()

    if existe_email.data:
        flash("El correo electrónico ya está registrado.", "danger")

        response = supabase.table("usuarios") \
            .select("*") \
            .order("fecha_registro", desc=True) \
            .execute()

        usuarios = response.data

        return render_template("users.html", usuarios=usuarios, abrir_modal=True)


    # Validar documento
    existe_doc = supabase.table("usuarios") \
        .select("id") \
        .eq("documento", documento) \
        .execute()

    if existe_doc.data:
        flash("Ya existe un usuario con esa cédula.", "danger")
        
        response = supabase.table("usuarios") \
            .select("*") \
            .order("fecha_registro", desc=True) \
            .execute()

        usuarios = response.data

        return render_template("users.html", usuarios=usuarios, abrir_modal=True)

    # Insertar
    supabase.table("usuarios").insert({
        "nombres": nombres,
        "apellidos": apellidos,
        "documento": documento,
        "email": email,
        "rol": rol,
        "password": password,
        "estado": True
    }).execute()

    flash("Usuario creado correctamente.", "success")
    return redirect(url_for("usuarios"))


# -----------------------
# EDITAR USUARIO
# -----------------------
@app.route("/usuarios/editar/<int:id>", methods=["POST"])
def editar_usuario(id):

    nombres = request.form["nombres"]
    apellidos = request.form["apellidos"]
    documento = request.form["documento"]
    email = request.form["email"]
    direccion = request.form.get("direccion")
    telefono = request.form.get("telefono")
    rol = request.form["rol"]

    # Validar email repetido (excepto el mismo usuario)
    existe_email = supabase.table("usuarios") \
        .select("id") \
        .eq("email", email) \
        .neq("id", id) \
        .execute()

    if existe_email.data:
        flash("El correo ya pertenece a otro usuario.", "danger")
        return redirect(url_for("usuarios"))

    # Actualizar
    supabase.table("usuarios") \
        .update({
            "nombres": nombres,
            "apellidos": apellidos,
            "documento": documento,
            "email": email,
            "direccion": direccion,
            "telefono": telefono,
            "rol": rol
        }) \
        .eq("id", id) \
        .execute()

    flash("Usuario actualizado correctamente.", "success")
    return redirect(url_for("usuarios"))

# -----------------------
# ELIMINAR USUARIO
# -----------------------

@app.route("/usuarios/eliminar/<int:id>")
def eliminar_usuario(id):

    supabase.table("usuarios") \
        .delete() \
        .eq("id", id) \
        .execute()

    flash("Usuario eliminado correctamente.", "danger")
    return redirect(url_for("usuarios"))

# -----------------------
# VER USUARIO
# -----------------------

@app.route('/usuarios/ver/<int:id>')
def ver_usuario(id):
    return f"ver usuario {id}"


# -----------------------
# INACTIVAR USUARIO O ACTIVAR
# -----------------------

@app.route("/usuarios/toggle/<int:user_id>", methods=["POST"])
def toggle_usuario(user_id):

    response = supabase.table("usuarios") \
        .select("estado") \
        .eq("id", user_id) \
        .single() \
        .execute()

    usuario = response.data
    nuevo_estado = not usuario["estado"]

    supabase.table("usuarios") \
        .update({"estado": nuevo_estado}) \
        .eq("id", user_id) \
        .execute()

    if nuevo_estado:
        flash("Usuario activado correctamente.", "success")
    else:
        flash("Usuario inactivado correctamente.", "danger")

    return redirect(url_for("usuarios"))


# -----------
# CREAR RUTAS
# -----------------------
@app.route("/rutas/crear", methods=["POST"])
def crear_ruta():

    if "oficina_id" not in session:
        return redirect(url_for("cambiar_oficina"))

    oficina_id = session["oficina_id"]

    posicion = request.form["posicion"]
    nombre = request.form["nombre"]
    tasa = request.form["tasa"]
    venta_maxima = request.form["venta_maxima"]

    # 🔥 USAR EL MISMO USER_ID DE LA SESIÓN
    usuario_id = session["user_id"]

    codigo = generar_codigo_ruta()

    supabase.table("rutas").insert({
        "posicion": posicion,
        "codigo": codigo,
        "nombre": nombre,
        "tasa": tasa,
        "venta_maxima": venta_maxima,
        "usuario_id": usuario_id,   # 🔥 AQUÍ
        "oficina_id": oficina_id,
        "estado": True
    }).execute()

    flash("Ruta creada correctamente", "success")
    return redirect(url_for("listar_rutas"))




@app.route("/oficinas")
def listar_oficinas():

    print("ENTRANDO A LISTAR OFICINAS 🔥")

    response = supabase.table("oficinas") \
        .select("*, rutas(*)") \
        .execute()

    print("RESPUESTA SUPABASE:", response)

    oficinas = response.data
    print("DATA:", oficinas)

    return render_template("oficinas.html", oficinas=oficinas)

@app.route("/rutas")
def listar_rutas():

    if "oficina_id" not in session:
        return redirect(url_for("cambiar_oficina"))

    oficina_id = session["oficina_id"]

    rutas = supabase.table("rutas") \
        .select("*, usuarios(*)") \
        .eq("oficina_id", oficina_id) \
        .order("posicion") \
        .execute()

    usuarios = supabase.table("usuarios") \
        .select("id, nombres, apellidos, rol") \
        .in_("rol", ["Supervisor", "Cobrador"]) \
        .execute()

    return render_template(
        "rutas.html",
        rutas=rutas.data or [],
        usuarios=usuarios.data or []
    )


# -----------------------
# ESTADO RUTAS
# -----------------------

@app.route("/rutas/toggle/<int:id>", methods=["POST"])
def toggle_ruta(id):

    ruta = supabase.table("rutas") \
        .select("estado") \
        .eq("id", id) \
        .single() \
        .execute()

    nuevo_estado = not ruta.data["estado"]

    supabase.table("rutas") \
        .update({"estado": nuevo_estado}) \
        .eq("id", id) \
        .execute()

    return redirect(url_for("listar_rutas"))

## -----------------------
# LISTAR VENTAS ACTIVAS
# -----------------------
from datetime import date

@app.route("/ventas")
def listar_ventas():

    ruta_id = request.args.get("ruta_id")
    buscar = request.args.get("buscar", "").strip().lower()
    filtro_mora = request.args.get("filtro_mora")

    rutas = supabase.table("rutas").select("*").execute().data

    ventas = []
    saldo_total = 0

    if ruta_id:

        response = supabase.table("creditos") \
            .select("id, cliente_id, posicion, valor_venta, valor_total, created_at, clientes(nombre, identificacion)") \
            .eq("ruta_id", ruta_id) \
            .execute()

        creditos = response.data

        for c in creditos:

            cliente_nombre = c["clientes"]["nombre"]
            identificacion = c["clientes"]["identificacion"]

            # 🔎 BUSCADOR
            if buscar:
                if buscar not in cliente_nombre.lower() and buscar not in identificacion.lower():
                    continue

            cuotas = supabase.table("cuotas") \
                .select("valor, estado, fecha_pago") \
                .eq("credito_id", c["id"]) \
                .execute().data

            total_pagado = 0
            dias_mora = 0

            for cuota in cuotas:

                if cuota["estado"] == "pagado":
                    total_pagado += float(cuota["valor"])

                if cuota["estado"] == "pendiente":
                    fecha_pago = date.fromisoformat(cuota["fecha_pago"])
                    if fecha_pago < date.today():
                        dias_mora += (date.today() - fecha_pago).days

            saldo = float(c["valor_total"]) - total_pagado

            # 🔥 FILTRO POR MORA
            if filtro_mora == "21" and dias_mora < 21:
                continue
            if filtro_mora == "11" and (dias_mora < 11 or dias_mora >= 21):
                continue
            if filtro_mora == "0" and dias_mora > 0:
                continue

            ventas.append({
                "posicion": c["posicion"],
                "codigo": c["id"][:8],
                "valor_venta": "{:,.0f}".format(c["valor_venta"]),
                "valor_total": "{:,.0f}".format(c["valor_total"]),
                "saldo": "{:,.0f}".format(saldo),
                "cliente": cliente_nombre,
                "identificacion": identificacion,
                "fecha_registro": c["created_at"][:10],
                "dias_mora": dias_mora,
                "cliente_id": c["cliente_id"],

            })

            saldo_total += saldo

    return render_template(
        "ventas.html",
        rutas=rutas,
        ventas=ventas,
        ruta_id=int(ruta_id) if ruta_id else None,
        saldo_total=saldo_total
    )






# =============================
# NUEVA VENTA (CONTROL FLUJO)
# =============================
@app.route("/nueva_venta")
def nueva_venta():

    # 🔹 Traer rutas
    rutas_resp = supabase.table("rutas").select("*").execute()
    rutas = rutas_resp.data if rutas_resp.data else []

    cliente = None
    valor_anterior = None

    # 🔹 Si viene cliente en sesión (normal o renovación)
    cliente_id = session.get("cliente_id")

    if cliente_id:
        cliente_resp = supabase.table("clientes") \
            .select("*") \
            .eq("id", cliente_id) \
            .execute()

        if cliente_resp.data:
            cliente = cliente_resp.data[0]

    # 🔹 Si es renovación, traer valor anterior
    valor_anterior = session.get("valor_anterior")

    return render_template(
        "nueva_venta.html",
        rutas=rutas,
        cliente=cliente,
        valor_anterior=valor_anterior
    )



@app.route("/cancelar_venta")
def cancelar_venta():

    session.pop("cliente_id", None)

    flash("Venta pendiente cancelada", "warning")

    return redirect(url_for("nueva_venta"))



# GUARDAR CLIENTE
@app.route("/guardar_cliente", methods=["POST"])
def guardar_cliente():

    nombre = request.form["nombre"]
    identificacion = request.form["identificacion"]
    telefono = request.form.get("telefono_principal")

    foto_url = None

    # 🔥 Si viene imagen
    if "foto" in request.files:
        foto = request.files["foto"]

        if foto.filename != "":
            filename = f"{identificacion}.jpg"

            # Subir a Supabase Storage
            supabase.storage.from_("clientes").upload(
                filename,
                foto.read(),
                {"content-type": foto.content_type}
            )

            # Obtener URL pública
            foto_url = supabase.storage.from_("clientes").get_public_url(filename)

    data = {
        "nombre": nombre,
        "identificacion": identificacion,
        "telefono_principal": telefono,
        "foto": foto_url
    }

    response = supabase.table("clientes").insert(data).execute()

    if response.data:
        session["cliente_id"] = response.data[0]["id"]
        flash("Cliente guardado correctamente", "success")
    else:
        flash("Error al guardar cliente", "error")

    return redirect(url_for("nueva_venta"))
    
@app.route("/buscar_cliente_renovacion", methods=["POST"])
def buscar_cliente_renovacion():

    identificacion = request.form.get("identificacion")

    # 🔎 Buscar cliente por cédula
    cliente_resp = supabase.table("clientes") \
        .select("*") \
        .eq("identificacion", identificacion) \
        .execute()

    if not cliente_resp.data:
        flash("Cliente no encontrado", "danger")
        return redirect(url_for("nueva_venta"))

    cliente = cliente_resp.data[0]

    # 🔎 Buscar todos los créditos del cliente
    creditos = supabase.table("creditos") \
        .select("id, valor_venta") \
        .eq("cliente_id", cliente["id"]) \
        .execute().data

    if not creditos:
        flash("El cliente no tiene créditos anteriores", "warning")
        return redirect(url_for("nueva_venta"))

    # 🔥 VALIDACIÓN REAL (NO usar estado del crédito)
    for credito in creditos:

        cuotas_pendientes = supabase.table("cuotas") \
            .select("id") \
            .eq("credito_id", credito["id"]) \
            .neq("estado", "pagado") \
            .execute()

        if cuotas_pendientes.data:
            flash("El cliente aún tiene saldo pendiente", "warning")
            return redirect(url_for("nueva_venta"))

    # 🔥 Si llega aquí → todos los créditos están pagados
    session["cliente_id"] = cliente["id"]
    session["valor_anterior"] = creditos[-1]["valor_venta"]

    flash("Cliente listo para renovación", "success")
    return redirect(url_for("nueva_venta"))


# LIMPIAR CLIENTE

@app.route("/limpiar_cliente")
def limpiar_cliente():

    session.pop("cliente_id", None)
    session.pop("valor_anterior", None)

    flash("Cliente removido correctamente", "warning")

    return redirect(url_for("nueva_venta"))


# LISTAR CREDITO
@app.route("/creditos")
def listar_creditos():

    filtro = request.args.get("mora")

    query = supabase.table("vista_creditos_mora").select("*")

    if filtro == "21":
        query = query.gte("dias_mora", 21)
    elif filtro == "11":
        query = query.gte("dias_mora", 11).lt("dias_mora", 21)
    elif filtro == "0":
        query = query.eq("dias_mora", 0)

    creditos = query.execute()

    return render_template("creditos.html", creditos=creditos.data)

# =============================
# GUARDAR VENTA
# =============================
@app.route("/guardar_venta", methods=["POST"])
def guardar_venta():

    cliente_id = session.get("cliente_id")

    if not cliente_id:
        flash("Debe seleccionar un cliente", "warning")
        return redirect(url_for("nueva_venta"))

    # 🔎 Validar si tiene crédito con cuotas pendientes
    creditos_cliente = supabase.table("creditos") \
        .select("id") \
        .eq("cliente_id", cliente_id) \
        .execute().data

    for credito in creditos_cliente:

        cuotas_pendientes = supabase.table("cuotas") \
            .select("id") \
            .eq("credito_id", credito["id"]) \
            .neq("estado", "pagado") \
            .execute()

        if cuotas_pendientes.data:
            flash("El cliente tiene un crédito con saldo pendiente", "error")
            return redirect(url_for("nueva_venta"))


    # 🔹 Datos del formulario
    valor_venta = float(request.form["valor_venta"])
    tasa = float(request.form["tasa"])
    cuotas = int(request.form["cuotas"])

    valor_total = valor_venta + (valor_venta * tasa / 100)
    valor_cuota = valor_total / cuotas

    # 🔹 Insertar nuevo crédito
    credito_data = {
        "cliente_id": cliente_id,
        "ruta_id": request.form["ruta_id"],
        "tipo_prestamo": request.form["tipo_prestamo"],
        "posicion": request.form["posicion"],
        "valor_venta": valor_venta,
        "tasa": tasa,
        "valor_total": valor_total,
        "cantidad_cuotas": cuotas,
        "valor_cuota": valor_cuota,
        "fecha_inicio": request.form["fecha_inicio"],
        "estado": "activo"
    }

    credito_resp = supabase.table("creditos").insert(credito_data).execute()

    if not credito_resp.data:
        flash("Error al registrar el crédito", "error")
        return redirect(url_for("nueva_venta"))

    credito_id = credito_resp.data[0]["id"]

    # 🔹 Crear cuotas automáticamente
    fecha_inicio = datetime.strptime(request.form["fecha_inicio"], "%Y-%m-%d")

    for i in range(cuotas):

        cuota_data = {
            "credito_id": credito_id,
            "numero": i + 1,
            "valor": valor_cuota,
            "estado": "pendiente",
            "fecha_pago": (fecha_inicio + timedelta(days=i)).date().isoformat()
        }

        supabase.table("cuotas").insert(cuota_data).execute()

    # 🔹 Si era renovación, marcar crédito anterior como renovado
    valor_anterior = session.get("valor_anterior")

    if valor_anterior:
        ultimo_credito = supabase.table("creditos") \
            .select("id") \
            .eq("cliente_id", cliente_id) \
            .neq("id", credito_id) \
            .order("created_at", desc=True) \
            .limit(1) \
            .execute()

        if ultimo_credito.data:
            supabase.table("creditos").update({
                "estado": "renovado"
            }).eq("id", ultimo_credito.data[0]["id"]).execute()

    # 🔹 Limpiar sesión
    session.pop("cliente_id", None)
    session.pop("valor_anterior", None)

    flash("Venta registrada correctamente", "success")

    return redirect(url_for("nueva_venta"))

# LISTAR PAGOS
@app.route("/pagos")
def vista_pagos():

    ruta_id = request.args.get("ruta_id")
    credito_id = request.args.get("credito_id")

    rutas = supabase.table("rutas").select("*").execute().data

    creditos = []
    credito_detalle = None
    cuotas = []
    saldo = 0

    if ruta_id:
        creditos = supabase.table("creditos") \
            .select("id, clientes(nombre)") \
            .eq("ruta_id", ruta_id) \
            .eq("estado", "activo") \
            .execute().data

    if credito_id:

        credito = supabase.table("creditos") \
            .select("*, clientes(*)") \
            .eq("id", credito_id) \
            .single() \
            .execute().data

        cuotas = supabase.table("cuotas") \
            .select("*") \
            .eq("credito_id", credito_id) \
            .order("numero") \
            .execute().data

        total_pagado = sum(float(c["valor"]) for c in cuotas if c["estado"] == "pagado")
        saldo = float(credito["valor_total"]) - total_pagado

        credito_detalle = credito

    return render_template(
        "registro_pagos/pagos.html",
        rutas=rutas,
        creditos=creditos,
        credito=credito_detalle,
        cuotas=cuotas,
        saldo=saldo
    )


# HISTORIAL DE CUOTAS

@app.route("/historial_creditos/<cliente_id>")
def historial_creditos(cliente_id):

    cliente = supabase.table("clientes") \
        .select("*") \
        .eq("id", cliente_id) \
        .single() \
        .execute().data

    creditos = supabase.table("creditos") \
        .select("*") \
        .eq("cliente_id", cliente_id) \
        .order("fecha_inicio", desc=True) \
        .execute().data

    # Traer cuotas por cada crédito
    for credito in creditos:

        cuotas_db = supabase.table("cuotas") \
            .select("*") \
            .eq("credito_id", credito["id"]) \
            .order("numero") \
            .execute().data

        cuotas = []
        total_pagado = 0

        for c in cuotas_db:

            dias_mora = 0

            if c["estado"] == "pendiente":
                fecha = date.fromisoformat(c["fecha_pago"])
                if fecha < date.today():
                    dias_mora = (date.today() - fecha).days

            if c["estado"] == "pagado":
                total_pagado += float(c["valor"])

            cuotas.append({
                "id": c["id"],
                "numero": c["numero"],
                "fecha_programada": c["fecha_pago"],
                "valor": c["valor"],
                "estado": c["estado"],
                "dias_mora": dias_mora
            })

        credito["cuotas"] = cuotas
        credito["total_pagado"] = total_pagado
        credito["saldo"] = float(credito["valor_total"]) - total_pagado

    return render_template(
        "historial_creditos/historial_creditos.html",
        cliente=cliente,
        creditos=creditos
    )


@app.route("/historial_cliente/<cliente_id>")
def historial_cliente(cliente_id):

    # 🔎 Traer cliente
    cliente_resp = supabase.table("clientes") \
        .select("*") \
        .eq("id", cliente_id) \
        .single() \
        .execute()

    if not cliente_resp.data:
        return redirect(url_for("dashboard_cobrador"))

    cliente = cliente_resp.data

    # 🔎 Traer todos los créditos del cliente
    creditos_resp = supabase.table("creditos") \
        .select("*") \
        .eq("cliente_id", cliente_id) \
        .order("created_at", desc=True) \
        .execute()

    creditos = creditos_resp.data if creditos_resp.data else []

    lista_creditos = []

    for c in creditos:

        cuotas = supabase.table("cuotas") \
            .select("valor, estado") \
            .eq("credito_id", c["id"]) \
            .execute().data

        total_pagado = sum(float(q["valor"]) for q in cuotas if q["estado"] == "pagado")
        saldo = float(c["valor_total"]) - total_pagado

        lista_creditos.append({
            "id": c["id"],
            "estado": c["estado"],
            "valor_total": c["valor_total"],
            "saldo": saldo,
            "fecha": c["created_at"][:10]
        })

    return render_template(
        "cobrador/historial_cliente.html",
        cliente=cliente,
        creditos=lista_creditos
    )

# LISTAR CLIENTES
@app.route("/clientes")
def clientes():

    clientes = supabase.table("clientes").select("*").execute().data
    rutas = supabase.table("rutas").select("*").execute().data

    return render_template("clientes.html",
                           clientes=clientes,
                           rutas=rutas)



# -----------------------
# MODULO CAPITAL
# -----------------------
@app.route("/capital")
def capital():


    return render_template("capital.html")



# -----------------------
# MODULO GASTOS
# -----------------------
@app.route("/gastos")
def gastos():

    gastos_data = [
        {
            "id": 55476,
            "fecha": "2026-02-07 08:01 PM",
            "ruta": "CENTRO",
            "descripcion": "SUELDO REVISADOR",
            "valor": 40.00,
            "categoria": "SUELDO"
        },
        {
            "id": 55469,
            "fecha": "2026-02-07 08:01 PM",
            "ruta": "CENTRO",
            "descripcion": "ACEITE",
            "valor": 12.00,
            "categoria": "ACEITE"
        },
        {
            "id": 55466,
            "fecha": "2026-02-07 08:00 PM",
            "ruta": "CENTRO",
            "descripcion": "Arreglo de cableada",
            "valor": 20.00,
            "categoria": "Otros"
        },
        {
            "id": 55464,
            "fecha": "2026-02-07 08:00 PM",
            "ruta": "CENTRO",
            "descripcion": "PASAJE REVISADOR",
            "valor": 30.00,
            "categoria": "PASAJE REVISADOR"
        }
    ]

    return render_template("gastos.html", gastos=gastos_data)


# -----------------------
# MODULO TRANSFERENCIAS
# -----------------------
@app.route("/transferencias")
def transferencias():

    # Datos simulados (luego lo conectas a BD)
    transferencias = [
        {
            "fecha": "2025-02-10",
            "ruta_entrega": "Ruta Norte",
            "ruta_recibe": "Ruta Centro",
            "valor": 250000,
            "descripcion": "Transferencia semanal"
        },
        {
            "fecha": "2025-02-11",
            "ruta_entrega": "Ruta Sur",
            "ruta_recibe": "Ruta Norte",
            "valor": 180000,
            "descripcion": "Ajuste operativo"
        }
    ]

    total = sum(t["valor"] for t in transferencias)

    return render_template(
        "transferencias.html",
        transferencias=transferencias,
        total=total,
        hoy=date.today()
    )

# -----------------------
# MODULO RETIROS
# -----------------------
# -----------------------
# MODULO RETIROS
# -----------------------
@app.route("/retiros")
def retiros():

    retiros = [
        {
            "id": 754,
            "fecha": "2025-12-27",
            "valor": 500000,
            "descripcion": "Reembolso don Jim",
            "ruta": "CENTRO"
        },
        {
            "id": 674,
            "fecha": "2025-12-19",
            "valor": 450000,
            "descripcion": "Intereses don Jim",
            "ruta": "4VIVIANA MILAGROS"
        },
        {
            "id": 614,
            "fecha": "2025-12-06",
            "valor": 725000,
            "descripcion": "Intereses noviembre",
            "ruta": "3MILAGROS"
        },
        {
            "id": 556,
            "fecha": "2025-11-29",
            "valor": 450000,
            "descripcion": "Intereses noviembre",
            "ruta": "4VIVIANA MILAGROS"
        }
    ]

    total = sum(r["valor"] for r in retiros)

    return render_template(
        "retiros.html",
        retiros=retiros,
        total=total,
        hoy=date.today()
    )


# -----------------------
# MODULO CAJA
# -----------------------
@app.route("/caja")
def caja():

    cajas = [
        {"ruta": "LIBRO ADMIN Y DEPOSITOS JM-LB", "saldo": 18254000},
        {"ruta": "1MILAGROS VICTOR RAMON", "saldo": 132250},
        {"ruta": "2MILAGROS ENRIQUE WILFRIDO", "saldo": 58950},
        {"ruta": "3MILAGROS CRISTHIAN GABRIEL", "saldo": 66250},
        {"ruta": "4VIVIANA MILAGROS GREYS VIVIANA", "saldo": -21500},
        {"ruta": "CENTRO ADONIRAN", "saldo": 263250},
        {"ruta": "BRAYAN LUIS FERNANDO", "saldo": 625250}
    ]

    resumen = {
        "saldo_anterior": 15000000,
        "total_recibido": 2450000,
        "total_cobros": 1850000,
        "total_prestamos": 950000,
        "total_gastos": 430000,
        "transferencias_retiros": 210000,
        "saldo_actual": 16710000
    }

    saldo_total = sum(c["saldo"] for c in cajas)

    return render_template(
        "cajas.html",
        cajas=cajas,
        resumen=resumen,
        saldo_total=saldo_total
    )

# -----------------------
# MODULO CAJA
# -----------------------
@app.route("/reportes")
def reportes():

    pestaña = request.args.get("tab", "ventas")

    # -------------------------
    # DATOS SIMULADOS
    # -------------------------

    ventas = [
        {
            "cliente": "Juan Pérez",
            "total_venta": 500000,
            "tasa": "10%",
            "interes": 50000,
            "total": 550000,
            "saldo": 200000,
            "fecha_registro": "2026-02-01",
            "fecha_final": "2026-02-10",
            "registrado": "Mauricio"
        }
    ]

    liquidacion = [
        {
            "ruta": "Ruta Norte",
            "total_cobrado": 1200000,
            "total_prestamos": 900000,
            "total_gastos": 150000,
            "saldo": 150000
        }
    ]

    return render_template(
        "reportes.html",
        pestaña=pestaña,
        ventas=ventas,
        liquidacion=liquidacion,
        hoy=date.today()
    )

# -----------------------
# DASHBOARD PRINCIPAL
# -----------------------
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    if "oficina_id" not in session:
        return redirect(url_for("cambiar_oficina"))

    return render_template("dashboard.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/usuarios/nuevo")
def nuevo_usuario():
    return render_template("nuevo_usuario.html")


if __name__ == "__main__":
    app.run(debug=True)


