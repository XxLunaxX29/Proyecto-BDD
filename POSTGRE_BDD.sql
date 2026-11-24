-- =================================================================================================
-- TECNOLÓGICO NACIONAL DE MÉXICO - INSTITUTO TECNOLÓGICO SUPERIOR DE MONCLOVA
-- PROYECTO INTEGRADOR V - INGENIERÍA INFORMÁTICA
-- SISTEMA E-COMMERCE DE CUIDADO DE LA SALUD, BELLEZA Y MAQUILLAJE
-- =================================================================================================
-- SGBD DESTINO: PostgreSQL 12+ (Convertido desde T-SQL / SQL Server 2019/2022)
-- TOTAL DE TABLAS EN ESTE SCRIPT: 150 Tablas Normalizadas (1FN, 2FN, 3FN, BCNF, 4FN)
-- =================================================================================================

-- Opcional: Descomentar para recrear la base de datos en psql como superusuario:
-- DROP DATABASE IF EXISTS ecommerce_salud_belleza_db;
-- CREATE DATABASE ecommerce_salud_belleza_db WITH ENCODING 'UTF8';
-- \c ecommerce_salud_belleza_db;

-- =================================================================================================
-- TECNOLÓGICO NACIONAL DE MÉXICO - INSTITUTO TECNOLÓGICO SUPERIOR DE MONCLOVA
-- PROYECTO INTEGRADOR V - INGENIERÍA INFORMÁTICA
-- SISTEMA E-COMMERCE DE CUIDADO DE LA SALUD, BELLEZA Y MAQUILLAJE
-- =================================================================================================
-- SUBMÓDULO 1: IDENTIDAD, CONTROL DE ACCESO, PERFIL DERMO-SALUD, CATÁLOGO Y COFEPRIS
-- AUTOR / INTEGRANTE 1: Estudiante 1 (Responsable de Tablas 001 a 050)
-- SGBD DESTINO: PostgreSQL 12+
-- TOTAL DE TABLAS EN ESTE SCRIPT: 50 Tablas Normalizadas (1FN, 2FN, 3FN, BCNF, 4FN)
-- CRITERIO DE AUDITORÍA: Cada tabla implementa ID autoincrementable y las 7 columnas de trazabilidad
-- y borrado lógico (Soft Delete) conforme a la LFPDPPP y Código Penal Federal.
-- =================================================================================================





-- Crear esquemas lógicos para modularidad y separación de responsabilidades
CREATE SCHEMA IF NOT EXISTS seguridad;
CREATE SCHEMA IF NOT EXISTS clientes;
CREATE SCHEMA IF NOT EXISTS catalogo;
CREATE SCHEMA IF NOT EXISTS comunidad;

-- =================================================================================================
-- SECCIÓN 1.1: SEGURIDAD, IAM Y CONTROL DE ACCESO CRIPTOGRÁFICO (TABLAS 001 - 010)
-- =================================================================================================

-- 001. TABLA: seguridad.roles (Catálogo 1)
DROP TABLE IF EXISTS seguridad.roles CASCADE;
CREATE TABLE seguridad.roles (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_rol VARCHAR(30) NOT NULL,
    nombre_rol VARCHAR(80) NOT NULL,
    descripcion VARCHAR(255) NOT NULL,
    nivel_jerarquico INT NOT NULL CONSTRAINT CK_seguridad_roles_nivel CHECK (nivel_jerarquico BETWEEN 1 AND 10),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_seguridad_roles_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_roles_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_seguridad_roles PRIMARY KEY (ID),
    CONSTRAINT UQ_seguridad_roles_codigo UNIQUE (codigo_rol)
);

-- 002. TABLA: seguridad.permisos (Catálogo 2)
DROP TABLE IF EXISTS seguridad.permisos CASCADE;
CREATE TABLE seguridad.permisos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    clave_permiso VARCHAR(60) NOT NULL,
    modulo_sistema VARCHAR(50) NOT NULL,
    accion VARCHAR(30) NOT NULL,
    descripcion VARCHAR(255) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_seguridad_permisos_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_permisos_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_seguridad_permisos PRIMARY KEY (ID),
    CONSTRAINT UQ_seguridad_permisos_clave UNIQUE (clave_permiso)
);

-- 003. TABLA: seguridad.roles_permisos (Intermedia N:M)
DROP TABLE IF EXISTS seguridad.roles_permisos CASCADE;
CREATE TABLE seguridad.roles_permisos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_rol BIGINT NOT NULL,
    ID_permiso BIGINT NOT NULL,
    permitir BOOLEAN NOT NULL CONSTRAINT DF_seguridad_rp_permitir DEFAULT TRUE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_seguridad_rp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_rp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_seguridad_roles_permisos PRIMARY KEY (ID),
    CONSTRAINT UQ_seguridad_roles_permisos UNIQUE (ID_rol, ID_permiso),
    CONSTRAINT FK_seguridad_rp_rol FOREIGN KEY (ID_rol) REFERENCES seguridad.roles(ID),
    CONSTRAINT FK_seguridad_rp_permiso FOREIGN KEY (ID_permiso) REFERENCES seguridad.permisos(ID));

-- 004. TABLA: seguridad.usuarios (Maestra de Autenticación Criptográfica)
DROP TABLE IF EXISTS seguridad.usuarios CASCADE;
CREATE TABLE seguridad.usuarios (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    uuid_usuario UUID NOT NULL CONSTRAINT DF_seguridad_usr_uuid DEFAULT gen_random_uuid(),
    email VARCHAR(150) NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Almacenamiento seguro bcrypt / Argon2id
    password_salt VARCHAR(128) NOT NULL,
    telefono_movil VARCHAR(20) NULL,
    email_verificado BOOLEAN NOT NULL CONSTRAINT DF_seguridad_usr_ev DEFAULT FALSE,
    cuenta_bloqueada BOOLEAN NOT NULL CONSTRAINT DF_seguridad_usr_cb DEFAULT FALSE,
    fecha_bloqueo TIMESTAMP(3) NULL,
    intentos_fallidos_consecutivos INT NOT NULL CONSTRAINT DF_seguridad_usr_ifc DEFAULT 0,
    mfa_habilitado BOOLEAN NOT NULL CONSTRAINT DF_seguridad_usr_mfa DEFAULT FALSE,
    mfa_secreto VARCHAR(128) NULL,
    ultimo_login_exitoso TIMESTAMP(3) NULL,
    ultimo_cambio_password TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_usr_ucp DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_seguridad_usr_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_usr_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_seguridad_usuarios PRIMARY KEY (ID),
    CONSTRAINT UQ_seguridad_usuarios_email UNIQUE (email),
    CONSTRAINT UQ_seguridad_usuarios_uuid UNIQUE (uuid_usuario)
);

-- 005. TABLA: seguridad.usuarios_roles (Intermedia N:M)
DROP TABLE IF EXISTS seguridad.usuarios_roles CASCADE;
CREATE TABLE seguridad.usuarios_roles (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_usuario BIGINT NOT NULL,
    ID_rol BIGINT NOT NULL,
    fecha_asignacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_ur_fa DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_seguridad_ur_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_ur_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_seguridad_usuarios_roles PRIMARY KEY (ID),
    CONSTRAINT UQ_seguridad_usuarios_roles UNIQUE (ID_usuario, ID_rol),
    CONSTRAINT FK_seguridad_ur_usuario FOREIGN KEY (ID_usuario) REFERENCES seguridad.usuarios(ID),
    CONSTRAINT FK_seguridad_ur_rol FOREIGN KEY (ID_rol) REFERENCES seguridad.roles(ID));

-- 006. TABLA: seguridad.sesiones_activas (Transaccional)
DROP TABLE IF EXISTS seguridad.sesiones_activas CASCADE;
CREATE TABLE seguridad.sesiones_activas (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_usuario BIGINT NOT NULL,
    token_sesion_hash VARCHAR(128) NOT NULL,
    direccion_ip VARCHAR(45) NOT NULL,
    user_agent VARCHAR(350) NOT NULL,
    fecha_inicio TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_sa_fi DEFAULT CURRENT_TIMESTAMP,
    fecha_expiracion TIMESTAMP(3) NOT NULL,
    revocada BOOLEAN NOT NULL CONSTRAINT DF_seguridad_sa_revocada DEFAULT FALSE,
    fecha_revocacion TIMESTAMP(3) NULL,
    motivo_revocacion VARCHAR(100) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_seguridad_sa_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_sa_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_seguridad_sesiones_activas PRIMARY KEY (ID),
    CONSTRAINT UQ_seguridad_sa_token UNIQUE (token_sesion_hash),
    CONSTRAINT FK_seguridad_sa_usuario FOREIGN KEY (ID_usuario) REFERENCES seguridad.usuarios(ID));

-- 007. TABLA: seguridad.historial_passwords (Transaccional / Criptografía)
DROP TABLE IF EXISTS seguridad.historial_passwords CASCADE;
CREATE TABLE seguridad.historial_passwords (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_usuario BIGINT NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    password_salt VARCHAR(128) NOT NULL,
    algoritmo_hashing VARCHAR(30) NOT NULL CONSTRAINT DF_seguridad_hp_alg DEFAULT 'Argon2id',
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_seguridad_hp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_hp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_seguridad_historial_passwords PRIMARY KEY (ID),
    CONSTRAINT FK_seguridad_hp_usuario FOREIGN KEY (ID_usuario) REFERENCES seguridad.usuarios(ID));

-- 008. TABLA: seguridad.intentos_login (Bitácora de Seguridad Forense)
DROP TABLE IF EXISTS seguridad.intentos_login CASCADE;
CREATE TABLE seguridad.intentos_login (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    email_ingresado VARCHAR(150) NOT NULL,
    ID_usuario BIGINT NULL, -- Null si el usuario no existe en la BD
    direccion_ip VARCHAR(45) NOT NULL,
    pais_origen_ip VARCHAR(60) NULL,
    user_agent VARCHAR(350) NOT NULL,
    resultado VARCHAR(20) NOT NULL CONSTRAINT CK_seguridad_il_res CHECK (resultado IN ('EXITOSO', 'PASSWORD_INVALIDO', 'USUARIO_INEXISTENTE', 'CUENTA_BLOQUEADA', 'MFA_FALLIDO')),
    mensaje_detalle VARCHAR(200) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_seguridad_il_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_il_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_seguridad_intentos_login PRIMARY KEY (ID),
    CONSTRAINT FK_seguridad_il_usuario FOREIGN KEY (ID_usuario) REFERENCES seguridad.usuarios(ID));

-- 009. TABLA: seguridad.tokens_recuperacion (Transaccional)
DROP TABLE IF EXISTS seguridad.tokens_recuperacion CASCADE;
CREATE TABLE seguridad.tokens_recuperacion (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_usuario BIGINT NOT NULL,
    token_hash VARCHAR(128) NOT NULL,
    tipo_token VARCHAR(30) NOT NULL CONSTRAINT CK_seguridad_tr_tipo CHECK (tipo_token IN ('RESET_PASSWORD', 'VERIFICAR_EMAIL', 'MFA_BACKUP')),
    fecha_expiracion TIMESTAMP(3) NOT NULL,
    utilizado BOOLEAN NOT NULL CONSTRAINT DF_seguridad_tr_utilizado DEFAULT FALSE,
    fecha_utilizacion TIMESTAMP(3) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_seguridad_tr_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_tr_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_seguridad_tokens_recuperacion PRIMARY KEY (ID),
    CONSTRAINT UQ_seguridad_tr_token UNIQUE (token_hash),
    CONSTRAINT FK_seguridad_tr_usuario FOREIGN KEY (ID_usuario) REFERENCES seguridad.usuarios(ID));

-- 010. TABLA: seguridad.dispositivos_confianza (Transaccional)
DROP TABLE IF EXISTS seguridad.dispositivos_confianza CASCADE;
CREATE TABLE seguridad.dispositivos_confianza (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_usuario BIGINT NOT NULL,
    fingerprint_dispositivo VARCHAR(128) NOT NULL,
    nombre_dispositivo VARCHAR(100) NOT NULL,
    sistema_operativo VARCHAR(60) NOT NULL,
    navegador VARCHAR(60) NOT NULL,
    es_confiable BOOLEAN NOT NULL CONSTRAINT DF_seguridad_dc_confiable DEFAULT TRUE,
    ultimo_acceso TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_dc_ua DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_seguridad_dc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_seguridad_dc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_seguridad_dispositivos_confianza PRIMARY KEY (ID),
    CONSTRAINT UQ_seguridad_dc_fingerprint UNIQUE (ID_usuario, fingerprint_dispositivo),
    CONSTRAINT FK_seguridad_dc_usuario FOREIGN KEY (ID_usuario) REFERENCES seguridad.usuarios(ID));

-- =================================================================================================
-- SECCIÓN 1.2: CLIENTES, PERFIL DERMO-SALUD Y CUMPLIMIENTO LFPDPPP (TABLAS 011 - 025)
-- =================================================================================================

-- 011. TABLA: clientes.tipos_piel (Catálogo 3)
DROP TABLE IF EXISTS clientes.tipos_piel CASCADE;
CREATE TABLE clientes.tipos_piel (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_piel VARCHAR(20) NOT NULL,
    nombre VARCHAR(50) NOT NULL,
    descripcion_clinica VARCHAR(255) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_tp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_tp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_tipos_piel PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_tp_codigo UNIQUE (codigo_piel)
);

-- 012. TABLA: clientes.condiciones_dermatologicas (Catálogo 4)
DROP TABLE IF EXISTS clientes.condiciones_dermatologicas CASCADE;
CREATE TABLE clientes.condiciones_dermatologicas (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_condicion VARCHAR(30) NOT NULL,
    nombre_condicion VARCHAR(80) NOT NULL,
    descripcion_patologica VARCHAR(255) NOT NULL,
    nivel_severidad_tipica VARCHAR(20) NOT NULL CONSTRAINT CK_clientes_cd_sev CHECK (nivel_severidad_tipica IN ('LEVE', 'MODERADA', 'SEVERA')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_cd_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_cd_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_condiciones_dermatologicas PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_cd_codigo UNIQUE (codigo_condicion)
);

-- 013. TABLA: clientes.clientes (Maestra de Clientes)
DROP TABLE IF EXISTS clientes.clientes CASCADE;
CREATE TABLE clientes.clientes (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_usuario BIGINT NOT NULL,
    nombres VARCHAR(80) NOT NULL,
    primer_apellido VARCHAR(60) NOT NULL,
    segundo_apellido VARCHAR(60) NULL,
    fecha_nacimiento DATE NOT NULL,
    genero VARCHAR(20) NULL CONSTRAINT CK_clientes_cli_gen CHECK (genero IN ('FEMENINO', 'MASCULINO', 'NO_BINARIO', 'PREFIERO_NO_DECIR')),
    curp VARCHAR(18) NULL,
    rfc VARCHAR(13) NULL,
    telefono_fijo VARCHAR(20) NULL,
    acepta_terminos BOOLEAN NOT NULL CONSTRAINT DF_clientes_cli_at DEFAULT TRUE,
    fecha_aceptacion_terminos TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_cli_fat DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_cli_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_cli_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_clientes PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_cli_usuario UNIQUE (ID_usuario),
    CONSTRAINT FK_clientes_cli_usuario FOREIGN KEY (ID_usuario) REFERENCES seguridad.usuarios(ID));

-- 014. TABLA: clientes.direcciones (Transaccional)
DROP TABLE IF EXISTS clientes.direcciones CASCADE;
CREATE TABLE clientes.direcciones (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    alias_direccion VARCHAR(50) NOT NULL, -- Ej: Casa, Trabajo
    calle VARCHAR(120) NOT NULL,
    numero_exterior VARCHAR(20) NOT NULL,
    numero_interior VARCHAR(20) NULL,
    colonia VARCHAR(100) NOT NULL,
    codigo_postal VARCHAR(10) NOT NULL,
    municipio_alcaldia VARCHAR(100) NOT NULL,
    estado VARCHAR(80) NOT NULL,
    pais VARCHAR(60) NOT NULL CONSTRAINT DF_clientes_dir_pais DEFAULT 'México',
    referencias VARCHAR(255) NULL,
    es_predeterminada_envio BOOLEAN NOT NULL CONSTRAINT DF_clientes_dir_pe DEFAULT FALSE,
    es_predeterminada_facturacion BOOLEAN NOT NULL CONSTRAINT DF_clientes_dir_pf DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_dir_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_dir_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_direcciones PRIMARY KEY (ID),
    CONSTRAINT FK_clientes_dir_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID));

-- 015. TABLA: clientes.perfil_cutaneo (Transaccional / Datos Sensibles de Salud LFPDPPP)
DROP TABLE IF EXISTS clientes.perfil_cutaneo CASCADE;
CREATE TABLE clientes.perfil_cutaneo (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    ID_tipo_piel BIGINT NOT NULL,
    sensibilidad_solar VARCHAR(30) NOT NULL CONSTRAINT CK_clientes_pc_solar CHECK (sensibilidad_solar IN ('MUY_BAJA', 'MODERADA', 'ALTA', 'EXTREMA')),
    nivel_oleosidad VARCHAR(20) NOT NULL CONSTRAINT CK_clientes_pc_oleo CHECK (nivel_oleosidad IN ('SECA', 'EQUILIBRADA', 'ZONA_T', 'GRASA_TOTAL')),
    poros_dilatados BOOLEAN NOT NULL CONSTRAINT DF_clientes_pc_poros DEFAULT FALSE,
    propension_acne BOOLEAN NOT NULL CONSTRAINT DF_clientes_pc_acne DEFAULT FALSE,
    manchas_hiperpigmentacion BOOLEAN NOT NULL CONSTRAINT DF_clientes_pc_manchas DEFAULT FALSE,
    lineas_expresion BOOLEAN NOT NULL CONSTRAINT DF_clientes_pc_lineas DEFAULT FALSE,
    consentimiento_datos_sensibles BOOLEAN NOT NULL CONSTRAINT DF_clientes_pc_cds DEFAULT TRUE,
    fecha_declaracion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_pc_fd DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_pc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_pc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_perfil_cutaneo PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_pc_cliente UNIQUE (ID_cliente),
    CONSTRAINT FK_clientes_pc_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID),
    CONSTRAINT FK_clientes_pc_tipo_piel FOREIGN KEY (ID_tipo_piel) REFERENCES clientes.tipos_piel(ID));

-- 016. TABLA: clientes.cliente_condiciones (Intermedia N:M)
DROP TABLE IF EXISTS clientes.cliente_condiciones CASCADE;
CREATE TABLE clientes.cliente_condiciones (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    ID_condicion_dermatologica BIGINT NOT NULL,
    diagnosticada_por_medico BOOLEAN NOT NULL CONSTRAINT DF_clientes_cc_dpm DEFAULT FALSE,
    notas_paciente VARCHAR(255) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_cc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_cc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_cliente_condiciones PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_cc_cliente_condicion UNIQUE (ID_cliente, ID_condicion_dermatologica),
    CONSTRAINT FK_clientes_cc_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID),
    CONSTRAINT FK_clientes_cc_condicion FOREIGN KEY (ID_condicion_dermatologica) REFERENCES clientes.condiciones_dermatologicas(ID));

-- 017. TABLA: clientes.cuestionarios_diagnostico (Maestra)
DROP TABLE IF EXISTS clientes.cuestionarios_diagnostico CASCADE;
CREATE TABLE clientes.cuestionarios_diagnostico (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_cuestionario VARCHAR(30) NOT NULL,
    titulo VARCHAR(120) NOT NULL,
    descripcion VARCHAR(255) NOT NULL,
    version_clinica VARCHAR(10) NOT NULL,
    vigente_desde DATE NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_cdiag_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_cdiag_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_cuestionarios_diagnostico PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_cdiag_codigo UNIQUE (codigo_cuestionario)
);

-- 018. TABLA: clientes.preguntas_diagnostico (Maestra)
DROP TABLE IF EXISTS clientes.preguntas_diagnostico CASCADE;
CREATE TABLE clientes.preguntas_diagnostico (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cuestionario BIGINT NOT NULL,
    numero_orden INT NOT NULL,
    enunciado_pregunta VARCHAR(255) NOT NULL,
    tipo_respuesta VARCHAR(30) NOT NULL CONSTRAINT CK_clientes_pd_tr CHECK (tipo_respuesta IN ('OPCION_UNICA', 'OPCION_MULTIPLE', 'ESCALA_NUMERICA')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_pd_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_pd_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_preguntas_diagnostico PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_pd_orden UNIQUE (ID_cuestionario, numero_orden),
    CONSTRAINT FK_clientes_pd_cuestionario FOREIGN KEY (ID_cuestionario) REFERENCES clientes.cuestionarios_diagnostico(ID));

-- 019. TABLA: clientes.opciones_pregunta (Maestra)
DROP TABLE IF EXISTS clientes.opciones_pregunta CASCADE;
CREATE TABLE clientes.opciones_pregunta (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_pregunta BIGINT NOT NULL,
    clave_opcion VARCHAR(20) NOT NULL,
    texto_opcion VARCHAR(150) NOT NULL,
    peso_clinico_puntos INT NOT NULL CONSTRAINT DF_clientes_op_peso DEFAULT 0,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_op_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_op_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_opciones_pregunta PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_op_pregunta_clave UNIQUE (ID_pregunta, clave_opcion),
    CONSTRAINT FK_clientes_op_pregunta FOREIGN KEY (ID_pregunta) REFERENCES clientes.preguntas_diagnostico(ID));

-- 020. TABLA: clientes.evaluaciones_diagnostico (Transaccional)
DROP TABLE IF EXISTS clientes.evaluaciones_diagnostico CASCADE;
CREATE TABLE clientes.evaluaciones_diagnostico (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    ID_cuestionario BIGINT NOT NULL,
    fecha_realizacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_ed_fr DEFAULT CURRENT_TIMESTAMP,
    puntaje_total INT NOT NULL,
    diagnostico_sugerido VARCHAR(150) NOT NULL,
    observaciones_dermoconsultor VARCHAR(500) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_ed_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_ed_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_evaluaciones_diagnostico PRIMARY KEY (ID),
    CONSTRAINT FK_clientes_ed_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID),
    CONSTRAINT FK_clientes_ed_cuestionario FOREIGN KEY (ID_cuestionario) REFERENCES clientes.cuestionarios_diagnostico(ID));

-- 021. TABLA: clientes.respuestas_evaluacion (Transaccional)
DROP TABLE IF EXISTS clientes.respuestas_evaluacion CASCADE;
CREATE TABLE clientes.respuestas_evaluacion (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_evaluacion BIGINT NOT NULL,
    ID_pregunta BIGINT NOT NULL,
    ID_opcion_seleccionada BIGINT NOT NULL,
    valor_texto_adicional VARCHAR(255) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_re_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_re_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_respuestas_evaluacion PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_re_eval_preg UNIQUE (ID_evaluacion, ID_pregunta, ID_opcion_seleccionada),
    CONSTRAINT FK_clientes_re_evaluacion FOREIGN KEY (ID_evaluacion) REFERENCES clientes.evaluaciones_diagnostico(ID),
    CONSTRAINT FK_clientes_re_pregunta FOREIGN KEY (ID_pregunta) REFERENCES clientes.preguntas_diagnostico(ID),
    CONSTRAINT FK_clientes_re_opcion FOREIGN KEY (ID_opcion_seleccionada) REFERENCES clientes.opciones_pregunta(ID));

-- 022. TABLA: clientes.consentimientos_privacidad (Transaccional / Evidencia Legal LFPDPPP)
DROP TABLE IF EXISTS clientes.consentimientos_privacidad CASCADE;
CREATE TABLE clientes.consentimientos_privacidad (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    version_aviso_privacidad VARCHAR(20) NOT NULL, -- Ej: v1.0-2026
    acepta_finalidades_primarias BOOLEAN NOT NULL CONSTRAINT DF_clientes_cp_fp DEFAULT TRUE,
    acepta_finalidades_secundarias_marketing BOOLEAN NOT NULL CONSTRAINT DF_clientes_cp_fs DEFAULT FALSE,
    acepta_tratamiento_datos_salud_sensibles BOOLEAN NOT NULL CONSTRAINT DF_clientes_cp_dss DEFAULT TRUE,
    direccion_ip_firma VARCHAR(45) NOT NULL,
    medio_consentimiento VARCHAR(30) NOT NULL CONSTRAINT CK_clientes_cp_medio CHECK (medio_consentimiento IN ('CHECKBOX_DIGITAL', 'FIRMA_ELECTRONICA', 'EN_SUCURSAL')),
    fecha_consentimiento TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_cp_fc DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_cp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_cp_fcreacion DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_consentimientos_privacidad PRIMARY KEY (ID),
    CONSTRAINT FK_clientes_cp_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID));

-- 023. TABLA: clientes.solicitudes_arco (Transaccional / Gestión Derechos ARCO LFPDPPP)
DROP TABLE IF EXISTS clientes.solicitudes_arco CASCADE;
CREATE TABLE clientes.solicitudes_arco (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_solicitud VARCHAR(35) NOT NULL,
    ID_cliente BIGINT NOT NULL,
    tipo_derecho VARCHAR(20) NOT NULL CONSTRAINT CK_clientes_arco_tipo CHECK (tipo_derecho IN ('ACCESO', 'RECTIFICACION', 'CANCELACION', 'OPOSICION')),
    motivo_solicitud VARCHAR(500) NOT NULL,
    estado_tramite VARCHAR(20) NOT NULL CONSTRAINT CK_clientes_arco_est CHECK (estado_tramite IN ('RECIBIDA', 'EN_REVISION', 'DOCUMENTACION_REQUERIDA', 'PROCEDENTE', 'IMPROCEDENTE', 'CONCLUIDA')),
    fecha_limite_respuesta DATE NOT NULL, -- Plazo legal máximo de 20 días hábiles
    resolucion_juridica VARCHAR(1000) NULL,
    fecha_resolucion TIMESTAMP(3) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_arco_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_arco_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_solicitudes_arco PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_arco_folio UNIQUE (folio_solicitud),
    CONSTRAINT FK_clientes_arco_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID));

-- 024. TABLA: clientes.preferencias_comunicacion (Transaccional)
DROP TABLE IF EXISTS clientes.preferencias_comunicacion CASCADE;
CREATE TABLE clientes.preferencias_comunicacion (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    canal_email BOOLEAN NOT NULL CONSTRAINT DF_clientes_pcom_email DEFAULT TRUE,
    canal_sms BOOLEAN NOT NULL CONSTRAINT DF_clientes_pcom_sms DEFAULT FALSE,
    canal_whatsapp BOOLEAN NOT NULL CONSTRAINT DF_clientes_pcom_wa DEFAULT FALSE,
    notificaciones_ofertas BOOLEAN NOT NULL CONSTRAINT DF_clientes_pcom_ofertas DEFAULT TRUE,
    alertas_reabastecimiento_rutina BOOLEAN NOT NULL CONSTRAINT DF_clientes_pcom_reab DEFAULT TRUE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_pcom_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_pcom_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_preferencias_comunicacion PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_pcom_cliente UNIQUE (ID_cliente),
    CONSTRAINT FK_clientes_pcom_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID));

-- 025. TABLA: clientes.metodos_pago_tokenizados (Transaccional / PCI-DSS)
DROP TABLE IF EXISTS clientes.metodos_pago_tokenizados CASCADE;
CREATE TABLE clientes.metodos_pago_tokenizados (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    pasarela_emisor VARCHAR(30) NOT NULL, -- Stripe, MercadoPago
    token_tarjeta_pasarela VARCHAR(120) NOT NULL, -- Token generado por la pasarela, NUNCA datos planos
    marca_tarjeta VARCHAR(30) NOT NULL, -- Visa, MasterCard, Amex
    ultimos_cuatro_digitos VARCHAR(4) NOT NULL,
    mes_expiracion INT NOT NULL CONSTRAINT CK_clientes_mpt_mes CHECK (mes_expiracion BETWEEN 1 AND 12),
    anio_expiracion INT NOT NULL CONSTRAINT CK_clientes_mpt_anio CHECK (anio_expiracion >= 2026),
    titular_tarjeta_hash VARCHAR(128) NOT NULL,
    es_predeterminada BOOLEAN NOT NULL CONSTRAINT DF_clientes_mpt_pred DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_clientes_mpt_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_clientes_mpt_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_clientes_metodos_pago_tokenizados PRIMARY KEY (ID),
    CONSTRAINT UQ_clientes_mpt_token UNIQUE (token_tarjeta_pasarela),
    CONSTRAINT FK_clientes_mpt_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID));

-- =================================================================================================
-- SECCIÓN 1.3: CATÁLOGO DE SALUD, BELLEZA, MAQUILLAJE Y COFEPRIS (TABLAS 026 - 046)
-- =================================================================================================

-- 026. TABLA: catalogo.marcas (Maestra)
DROP TABLE IF EXISTS catalogo.marcas CASCADE;
CREATE TABLE catalogo.marcas (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_marca VARCHAR(30) NOT NULL,
    nombre_marca VARCHAR(100) NOT NULL,
    pais_origen VARCHAR(60) NOT NULL,
    sitio_web VARCHAR(200) NULL,
    es_dermocosmetica BOOLEAN NOT NULL CONSTRAINT DF_catalogo_marcas_dermo DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_marcas_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_marcas_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_marcas PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_marcas_codigo UNIQUE (codigo_marca)
);

-- 027. TABLA: catalogo.laboratorios_fabricantes (Maestra)
DROP TABLE IF EXISTS catalogo.laboratorios_fabricantes CASCADE;
CREATE TABLE catalogo.laboratorios_fabricantes (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    clave_laboratorio VARCHAR(30) NOT NULL,
    razon_social VARCHAR(150) NOT NULL,
    licencia_sanitaria VARCHAR(80) NOT NULL,
    pais VARCHAR(60) NOT NULL,
    certificacion_gmp_vigente BOOLEAN NOT NULL CONSTRAINT DF_catalogo_lab_gmp DEFAULT TRUE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_lab_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_lab_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_laboratorios_fabricantes PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_lab_clave UNIQUE (clave_laboratorio)
);

-- 028. TABLA: catalogo.categorias (Maestra Jerárquica)
DROP TABLE IF EXISTS catalogo.categorias CASCADE;
CREATE TABLE catalogo.categorias (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_categoria VARCHAR(30) NOT NULL,
    nombre_categoria VARCHAR(80) NOT NULL,
    descripcion VARCHAR(255) NOT NULL,
    ID_categoria_padre BIGINT NULL,
    nivel_arbol INT NOT NULL CONSTRAINT DF_catalogo_cat_nivel DEFAULT 1,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_cat_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_cat_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_categorias PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_cat_codigo UNIQUE (codigo_categoria),
    CONSTRAINT FK_catalogo_cat_padre FOREIGN KEY (ID_categoria_padre) REFERENCES catalogo.categorias(ID));

-- 029. TABLA: catalogo.subcategorias (Maestra)
DROP TABLE IF EXISTS catalogo.subcategorias CASCADE;
CREATE TABLE catalogo.subcategorias (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_categoria BIGINT NOT NULL,
    codigo_subcategoria VARCHAR(30) NOT NULL,
    nombre_subcategoria VARCHAR(80) NOT NULL,
    descripcion VARCHAR(255) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_subcat_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_subcat_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_subcategorias PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_subcat_codigo UNIQUE (codigo_subcategoria),
    CONSTRAINT FK_catalogo_subcat_categoria FOREIGN KEY (ID_categoria) REFERENCES catalogo.categorias(ID));

-- 030. TABLA: catalogo.tipos_aplicacion (Catálogo 5)
DROP TABLE IF EXISTS catalogo.tipos_aplicacion CASCADE;
CREATE TABLE catalogo.tipos_aplicacion (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_aplicacion VARCHAR(20) NOT NULL,
    nombre VARCHAR(50) NOT NULL, -- Rostro, Ojos, Labios, Cuello, Cuerpo, Capilar
    descripcion VARCHAR(200) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_ta_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_ta_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_tipos_aplicacion PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_ta_codigo UNIQUE (codigo_aplicacion)
);

-- 031. TABLA: catalogo.certificaciones_sanitarias (Catálogo 6)
DROP TABLE IF EXISTS catalogo.certificaciones_sanitarias CASCADE;
CREATE TABLE catalogo.certificaciones_sanitarias (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_certificacion VARCHAR(30) NOT NULL,
    nombre_certificacion VARCHAR(80) NOT NULL, -- Cruelty Free, Vegan, Orgánico USDA, ECOCERT, Hipoalergénico
    organismo_certificador VARCHAR(100) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_cert_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_cert_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_certificaciones_sanitarias PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_cert_codigo UNIQUE (codigo_certificacion)
);

-- 032. TABLA: catalogo.productos_maestros (Maestra de Productos)
DROP TABLE IF EXISTS catalogo.productos_maestros CASCADE;
CREATE TABLE catalogo.productos_maestros (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_marca BIGINT NOT NULL,
    ID_subcategoria BIGINT NOT NULL,
    ID_laboratorio BIGINT NOT NULL,
    ID_tipo_aplicacion BIGINT NOT NULL,
    ID_certificacion_sanitaria BIGINT NULL,
    codigo_producto VARCHAR(40) NOT NULL,
    nombre_comercial VARCHAR(150) NOT NULL,
    descripcion_corta VARCHAR(300) NOT NULL,
    descripcion_detallada TEXT NOT NULL,
    modo_empleo VARCHAR(1000) NOT NULL,
    requiere_prescripcion_medica BOOLEAN NOT NULL CONSTRAINT DF_catalogo_pm_rpm DEFAULT FALSE,
    factor_proteccion_solar_fps INT NULL CONSTRAINT CK_catalogo_pm_fps CHECK (factor_proteccion_solar_fps IS NULL OR factor_proteccion_solar_fps BETWEEN 0 AND 100),
    es_sensible_temperatura BOOLEAN NOT NULL CONSTRAINT DF_catalogo_pm_temp DEFAULT FALSE, -- Cadena de frío requerida
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_pm_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_pm_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_productos_maestros PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_pm_codigo UNIQUE (codigo_producto),
    CONSTRAINT FK_catalogo_pm_marca FOREIGN KEY (ID_marca) REFERENCES catalogo.marcas(ID),
    CONSTRAINT FK_catalogo_pm_subcat FOREIGN KEY (ID_subcategoria) REFERENCES catalogo.subcategorias(ID),
    CONSTRAINT FK_catalogo_pm_lab FOREIGN KEY (ID_laboratorio) REFERENCES catalogo.laboratorios_fabricantes(ID),
    CONSTRAINT FK_catalogo_pm_aplicacion FOREIGN KEY (ID_tipo_aplicacion) REFERENCES catalogo.tipos_aplicacion(ID),
    CONSTRAINT FK_catalogo_pm_certificacion FOREIGN KEY (ID_certificacion_sanitaria) REFERENCES catalogo.certificaciones_sanitarias(ID));

-- 033. TABLA: catalogo.subtonos_maquillaje (Catálogo 7)
DROP TABLE IF EXISTS catalogo.subtonos_maquillaje CASCADE;
CREATE TABLE catalogo.subtonos_maquillaje (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_subtono VARCHAR(20) NOT NULL,
    nombre_subtono VARCHAR(50) NOT NULL, -- Cálido (Warm), Frío (Cool), Neutro (Neutral), Oliva (Olive)
    descripcion VARCHAR(200) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_subt_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_subt_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_subtonos_maquillaje PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_subt_codigo UNIQUE (codigo_subtono)
);

-- 034. TABLA: catalogo.acabados_maquillaje (Catálogo 8)
DROP TABLE IF EXISTS catalogo.acabados_maquillaje CASCADE;
CREATE TABLE catalogo.acabados_maquillaje (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_acabado VARCHAR(20) NOT NULL,
    nombre_acabado VARCHAR(50) NOT NULL, -- Mate, Satinado, Glow/Radiante, Terciopelo, Brilloso
    descripcion VARCHAR(200) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_acab_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_acab_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_acabados_maquillaje PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_acab_codigo UNIQUE (codigo_acabado)
);

-- 035. TABLA: catalogo.variantes_sku (Transaccional de SKUs)
DROP TABLE IF EXISTS catalogo.variantes_sku CASCADE;
CREATE TABLE catalogo.variantes_sku (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_producto BIGINT NOT NULL,
    sku_codigo VARCHAR(50) NOT NULL,
    codigo_barras_ean13 VARCHAR(14) NOT NULL,
    nombre_presentacion VARCHAR(100) NOT NULL, -- Ej: Tono 210 Warm Nude 30ml
    contenido_neto_gramos_ml DECIMAL(8,2) NOT NULL,
    unidad_medida VARCHAR(10) NOT NULL CONSTRAINT CK_catalogo_vsku_um CHECK (unidad_medida IN ('ML', 'G', 'OZ', 'PZ')),
    precio_base_menudeo DECIMAL(12,2) NOT NULL CONSTRAINT CK_catalogo_vsku_precio CHECK (precio_base_menudeo > 0),
    costo_estandar_compra DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_vsku_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_vsku_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_variantes_sku PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_vsku_codigo UNIQUE (sku_codigo),
    CONSTRAINT UQ_catalogo_vsku_ean UNIQUE (codigo_barras_ean13),
    CONSTRAINT FK_catalogo_vsku_producto FOREIGN KEY (ID_producto) REFERENCES catalogo.productos_maestros(ID));

-- 036. TABLA: catalogo.tonos_variante (Transaccional / Extensión Maquillaje)
DROP TABLE IF EXISTS catalogo.tonos_variante CASCADE;
CREATE TABLE catalogo.tonos_variante (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    ID_subtono BIGINT NOT NULL,
    ID_acabado BIGINT NOT NULL,
    codigo_tono_color VARCHAR(30) NOT NULL,
    nombre_tono VARCHAR(60) NOT NULL,
    color_hexadecimal VARCHAR(7) NOT NULL CONSTRAINT CK_catalogo_tv_hex CHECK (color_hexadecimal ~ '^#[0-9A-Fa-f]{6}$'),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_tv_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_tv_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_tonos_variante PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_tv_sku UNIQUE (ID_variante_sku),
    CONSTRAINT FK_catalogo_tv_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID),
    CONSTRAINT FK_catalogo_tv_subtono FOREIGN KEY (ID_subtono) REFERENCES catalogo.subtonos_maquillaje(ID),
    CONSTRAINT FK_catalogo_tv_acabado FOREIGN KEY (ID_acabado) REFERENCES catalogo.acabados_maquillaje(ID));

-- 037. TABLA: catalogo.ingredientes_inci (Maestra Nomenclatura Internacional Cosmética)
DROP TABLE IF EXISTS catalogo.ingredientes_inci CASCADE;
CREATE TABLE catalogo.ingredientes_inci (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_cas VARCHAR(30) NULL, -- Identificador Chemical Abstracts Service
    nombre_inci VARCHAR(120) NOT NULL, -- Ej: Niacinamide, Hyaluronic Acid, Retinol
    nombre_comun VARCHAR(120) NOT NULL,
    funcion_principal VARCHAR(150) NOT NULL,
    es_comedogenico BOOLEAN NOT NULL CONSTRAINT DF_catalogo_inci_com DEFAULT FALSE,
    indice_comedogenico INT NOT NULL CONSTRAINT CK_catalogo_inci_ic CHECK (indice_comedogenico BETWEEN 0 AND 5),
    es_alergeno_frecuente BOOLEAN NOT NULL CONSTRAINT DF_catalogo_inci_aler DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_inci_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_inci_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_ingredientes_inci PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_inci_nombre UNIQUE (nombre_inci)
);

-- 038. TABLA: catalogo.alergenos_ingrediente (Transaccional)
DROP TABLE IF EXISTS catalogo.alergenos_ingrediente CASCADE;
CREATE TABLE catalogo.alergenos_ingrediente (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_ingrediente BIGINT NOT NULL,
    nombre_alergeno VARCHAR(80) NOT NULL,
    clasificacion_riesgo VARCHAR(30) NOT NULL CONSTRAINT CK_catalogo_ai_riesgo CHECK (clasificacion_riesgo IN ('BAJO', 'MEDIO', 'ALTO', 'MUY_SEVERO')),
    advertencia_etiqueta VARCHAR(255) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_ai_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_ai_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_alergenos_ingrediente PRIMARY KEY (ID),
    CONSTRAINT FK_catalogo_ai_ingrediente FOREIGN KEY (ID_ingrediente) REFERENCES catalogo.ingredientes_inci(ID));

-- 039. TABLA: catalogo.formula_ingredientes (Intermedia N:M con porcentaje - 4FN)
DROP TABLE IF EXISTS catalogo.formula_ingredientes CASCADE;
CREATE TABLE catalogo.formula_ingredientes (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_producto BIGINT NOT NULL,
    ID_ingrediente BIGINT NOT NULL,
    orden_en_etiqueta INT NOT NULL, -- Por norma sanitaria COFEPRIS se ordenan de mayor a menor concentración
    porcentaje_concentracion DECIMAL(5,2) NULL CONSTRAINT CK_catalogo_fi_porc CHECK (porcentaje_concentracion IS NULL OR (porcentaje_concentracion BETWEEN 0.01 AND 100.00)),
    es_principio_activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_fi_pa DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_fi_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_fi_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_formula_ingredientes PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_fi_producto_ingrediente UNIQUE (ID_producto, ID_ingrediente),
    CONSTRAINT FK_catalogo_fi_producto FOREIGN KEY (ID_producto) REFERENCES catalogo.productos_maestros(ID),
    CONSTRAINT FK_catalogo_fi_ingrediente FOREIGN KEY (ID_ingrediente) REFERENCES catalogo.ingredientes_inci(ID));

-- 040. TABLA: catalogo.registros_sanitarios_cofepris (Transaccional Regulatoria)
DROP TABLE IF EXISTS catalogo.registros_sanitarios_cofepris CASCADE;
CREATE TABLE catalogo.registros_sanitarios_cofepris (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_producto BIGINT NOT NULL,
    numero_registro_sanitario VARCHAR(60) NOT NULL,
    folio_ingreso_tramite VARCHAR(60) NOT NULL,
    fecha_emision DATE NOT NULL,
    fecha_vencimiento DATE NOT NULL,
    estatus_regulatorio VARCHAR(30) NOT NULL CONSTRAINT CK_catalogo_cof_est CHECK (estatus_regulatorio IN ('VIGENTE', 'EN_RENOVACION', 'SUSPENDIDO', 'VENCIDO')),
    documento_oficial_url VARCHAR(300) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_cof_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_cof_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_registros_sanitarios_cofepris PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_cof_numero UNIQUE (numero_registro_sanitario),
    CONSTRAINT UQ_catalogo_cof_producto UNIQUE (ID_producto),
    CONSTRAINT FK_catalogo_cof_producto FOREIGN KEY (ID_producto) REFERENCES catalogo.productos_maestros(ID));

-- 041. TABLA: catalogo.advertencias_contraindicaciones (Transaccional Médica)
DROP TABLE IF EXISTS catalogo.advertencias_contraindicaciones CASCADE;
CREATE TABLE catalogo.advertencias_contraindicaciones (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_producto BIGINT NOT NULL,
    tipo_advertencia VARCHAR(30) NOT NULL CONSTRAINT CK_catalogo_adv_tipo CHECK (tipo_advertencia IN ('EMBARAZO_LACTANCIA', 'FOTOSENSIBLE', 'USO_EXTERNO_EXCLUSIVO', 'HERIDAS_ABIERTAS', 'EVITAR_OJOS')),
    texto_advertencia VARCHAR(350) NOT NULL,
    medida_en_caso_ingestion VARCHAR(350) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_adv_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_adv_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_advertencias_contraindicaciones PRIMARY KEY (ID),
    CONSTRAINT FK_catalogo_adv_producto FOREIGN KEY (ID_producto) REFERENCES catalogo.productos_maestros(ID));

-- 042. TABLA: catalogo.multimedia_variantes (Transaccional)
DROP TABLE IF EXISTS catalogo.multimedia_variantes CASCADE;
CREATE TABLE catalogo.multimedia_variantes (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    tipo_archivo VARCHAR(20) NOT NULL CONSTRAINT CK_catalogo_mv_tipo CHECK (tipo_archivo IN ('FOTO_FRONTAL', 'FOTO_SWATCH_PIEL', 'FOTO_EMPAQUE', 'VIDEO_TUTORIAL')),
    url_recurso VARCHAR(350) NOT NULL,
    texto_alternativo_accesibilidad VARCHAR(150) NOT NULL,
    numero_orden INT NOT NULL,
    es_imagen_principal BOOLEAN NOT NULL CONSTRAINT DF_catalogo_mv_princ DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_mv_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_mv_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_multimedia_variantes PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_mv_sku_orden UNIQUE (ID_variante_sku, numero_orden),
    CONSTRAINT FK_catalogo_mv_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 043. TABLA: catalogo.kits_sets (Maestra de Sets y Rutinas Armadas)
DROP TABLE IF EXISTS catalogo.kits_sets CASCADE;
CREATE TABLE catalogo.kits_sets (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_kit VARCHAR(40) NOT NULL,
    nombre_kit VARCHAR(120) NOT NULL,
    descripcion VARCHAR(300) NOT NULL,
    descuento_porcentual_kit DECIMAL(5,2) NOT NULL CONSTRAINT CK_catalogo_kit_desc CHECK (descuento_porcentual_kit BETWEEN 0.00 AND 80.00),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_kit_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_kit_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_kits_sets PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_kit_codigo UNIQUE (codigo_kit)
);

-- 044. TABLA: catalogo.kits_items (Intermedia N:M)
DROP TABLE IF EXISTS catalogo.kits_items CASCADE;
CREATE TABLE catalogo.kits_items (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_kit BIGINT NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    cantidad_unidades INT NOT NULL CONSTRAINT CK_catalogo_ki_cant CHECK (cantidad_unidades >= 1),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_ki_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_ki_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_kits_items PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_ki_kit_sku UNIQUE (ID_kit, ID_variante_sku),
    CONSTRAINT FK_catalogo_ki_kit FOREIGN KEY (ID_kit) REFERENCES catalogo.kits_sets(ID),
    CONSTRAINT FK_catalogo_ki_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 045. TABLA: catalogo.productos_relacionados (Intermedia N:M Cross-Sell / Reemplazos)
DROP TABLE IF EXISTS catalogo.productos_relacionados CASCADE;
CREATE TABLE catalogo.productos_relacionados (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_producto_origen BIGINT NOT NULL,
    ID_producto_destino BIGINT NOT NULL,
    tipo_relacion VARCHAR(30) NOT NULL CONSTRAINT CK_catalogo_pr_tipo CHECK (tipo_relacion IN ('COMPLEMENTARIO', 'SUSTITUTO', 'PASO_SIGUIENTE_RUTINA')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_pr_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_pr_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_productos_relacionados PRIMARY KEY (ID),
    CONSTRAINT UQ_catalogo_pr_origen_destino UNIQUE (ID_producto_origen, ID_producto_destino),
    CONSTRAINT FK_catalogo_pr_origen FOREIGN KEY (ID_producto_origen) REFERENCES catalogo.productos_maestros(ID),
    CONSTRAINT FK_catalogo_pr_destino FOREIGN KEY (ID_producto_destino) REFERENCES catalogo.productos_maestros(ID));

-- 046. TABLA: catalogo.historial_precios_base (Bitácora Transaccional de Precios)
DROP TABLE IF EXISTS catalogo.historial_precios_base CASCADE;
CREATE TABLE catalogo.historial_precios_base (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    precio_anterior DECIMAL(12,2) NOT NULL,
    precio_nuevo DECIMAL(12,2) NOT NULL,
    motivo_cambio VARCHAR(200) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_catalogo_hp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_catalogo_hp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_catalogo_historial_precios_base PRIMARY KEY (ID),
    CONSTRAINT FK_catalogo_hp_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- =================================================================================================
-- SECCIÓN 1.4: COMUNIDAD, RUTINAS DE BELLEZA Y FIDELIZACIÓN (TABLAS 047 - 050)
-- =================================================================================================

-- 047. TABLA: comunidad.rutinas_belleza (Maestra)
DROP TABLE IF EXISTS comunidad.rutinas_belleza CASCADE;
CREATE TABLE comunidad.rutinas_belleza (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    nombre_rutina VARCHAR(100) NOT NULL, -- Ej: Rutina Facial Mañana Anti-Acné
    momento_dia VARCHAR(20) NOT NULL CONSTRAINT CK_comunidad_rb_momento CHECK (momento_dia IN ('MAÑANA', 'NOCHE', 'SEMANAL')),
    es_publica BOOLEAN NOT NULL CONSTRAINT DF_comunidad_rb_pub DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_comunidad_rb_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_comunidad_rb_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_comunidad_rutinas_belleza PRIMARY KEY (ID),
    CONSTRAINT FK_comunidad_rb_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID));

-- 048. TABLA: comunidad.rutinas_pasos (Transaccional)
DROP TABLE IF EXISTS comunidad.rutinas_pasos CASCADE;
CREATE TABLE comunidad.rutinas_pasos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_rutina BIGINT NOT NULL,
    numero_paso INT NOT NULL CONSTRAINT CK_comunidad_rp_paso CHECK (numero_paso BETWEEN 1 AND 15),
    nombre_fase VARCHAR(60) NOT NULL, -- 1 Limpieza, 2 Tónico, 3 Sérum, 4 Crema, 5 Protector Solar
    instrucciones_aplicacion VARCHAR(255) NULL,
    tiempo_espera_segundos INT NOT NULL CONSTRAINT DF_comunidad_rp_tespera DEFAULT 60,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_comunidad_rp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_comunidad_rp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_comunidad_rutinas_pasos PRIMARY KEY (ID),
    CONSTRAINT UQ_comunidad_rp_rutina_paso UNIQUE (ID_rutina, numero_paso),
    CONSTRAINT FK_comunidad_rp_rutina FOREIGN KEY (ID_rutina) REFERENCES comunidad.rutinas_belleza(ID));

-- 049. TABLA: comunidad.rutinas_productos (Intermedia N:M)
DROP TABLE IF EXISTS comunidad.rutinas_productos CASCADE;
CREATE TABLE comunidad.rutinas_productos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_rutina_paso BIGINT NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    es_producto_principal BOOLEAN NOT NULL CONSTRAINT DF_comunidad_rprod_princ DEFAULT TRUE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_comunidad_rprod_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_comunidad_rprod_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_comunidad_rutinas_productos PRIMARY KEY (ID),
    CONSTRAINT UQ_comunidad_rprod_paso_sku UNIQUE (ID_rutina_paso, ID_variante_sku),
    CONSTRAINT FK_comunidad_rprod_paso FOREIGN KEY (ID_rutina_paso) REFERENCES comunidad.rutinas_pasos(ID),
    CONSTRAINT FK_comunidad_rprod_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 050. TABLA: comunidad.listas_deseos (Transaccional Wishlists)
DROP TABLE IF EXISTS comunidad.listas_deseos CASCADE;
CREATE TABLE comunidad.listas_deseos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    nombre_lista VARCHAR(80) NOT NULL, -- Ej: Mis labiales favoritos, Skin Care Deseado
    es_publica BOOLEAN NOT NULL CONSTRAINT DF_comunidad_ld_pub DEFAULT FALSE,
    token_compartir VARCHAR(64) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_comunidad_ld_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_comunidad_ld_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_comunidad_listas_deseos PRIMARY KEY (ID),
    CONSTRAINT FK_comunidad_ld_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID));

-- =================================================================================================
-- TECNOLÓGICO NACIONAL DE MÉXICO - INSTITUTO TECNOLÓGICO SUPERIOR DE MONCLOVA
-- PROYECTO INTEGRADOR V - INGENIERÍA INFORMÁTICA
-- SISTEMA E-COMMERCE DE CUIDADO DE LA SALUD, BELLEZA Y MAQUILLAJE
-- =================================================================================================
-- SUBMÓDULO 2: MOTOR TRANSACCIONAL, SUSCRIPCIONES, PASARELAS DE PAGO, ANTIFRAUDE Y CFDI 4.0
-- AUTOR / INTEGRANTE 2: Estudiante 2 (Responsable de Tablas 051 a 100)
-- SGBD DESTINO: PostgreSQL 12+
-- TOTAL DE TABLAS EN ESTE SCRIPT: 50 Tablas Normalizadas (1FN, 2FN, 3FN, BCNF, 4FN)
-- CRITERIO DE AUDITORÍA: Cada tabla implementa ID autoincrementable y las 7 columnas de trazabilidad
-- y borrado lógico (Soft Delete) conforme a la LFPDPPP y Código Penal Federal.
-- =================================================================================================


-- Crear esquemas lógicos para el submódulo comercial, financiero y fiscal
CREATE SCHEMA IF NOT EXISTS ventas;
CREATE SCHEMA IF NOT EXISTS pagos;
CREATE SCHEMA IF NOT EXISTS fiscal;
CREATE SCHEMA IF NOT EXISTS promos;

-- =================================================================================================
-- SECCIÓN 2.1: CARRO, SUSCRIPCIONES Y PROMOCIONES DE CLIENTE (TABLAS 051 - 063)
-- =================================================================================================

-- 051. TABLA: ventas.tipos_descuento (Catálogo 9)
DROP TABLE IF EXISTS ventas.tipos_descuento CASCADE;
CREATE TABLE ventas.tipos_descuento (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_descuento VARCHAR(20) NOT NULL,
    nombre VARCHAR(50) NOT NULL, -- Porcentual, Monto Fijo, 2x1, Envío Gratis
    descripcion VARCHAR(200) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_td_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_td_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_tipos_descuento PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_td_codigo UNIQUE (codigo_descuento)
);

-- 052. TABLA: ventas.estados_orden (Catálogo 10)
DROP TABLE IF EXISTS ventas.estados_orden CASCADE;
CREATE TABLE ventas.estados_orden (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_estado VARCHAR(30) NOT NULL,
    nombre_estado VARCHAR(60) NOT NULL, -- PENDIENTE_PAGO, PAGADA, EN_PREPARACION_WMS, EN_TRANSITO, ENTREGADA, CANCELADA, REEMBOLSADA
    descripcion VARCHAR(255) NOT NULL,
    es_terminal BOOLEAN NOT NULL CONSTRAINT DF_ventas_eo_term DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_eo_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_eo_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_estados_orden PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_eo_codigo UNIQUE (codigo_estado)
);

-- 053. TABLA: ventas.motivos_cancelacion_orden (Catálogo 11)
DROP TABLE IF EXISTS ventas.motivos_cancelacion_orden CASCADE;
CREATE TABLE ventas.motivos_cancelacion_orden (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_motivo VARCHAR(30) NOT NULL,
    descripcion_motivo VARCHAR(200) NOT NULL,
    es_atribuible_cliente BOOLEAN NOT NULL CONSTRAINT DF_ventas_mc_cli DEFAULT TRUE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_mc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_mc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_motivos_cancelacion_orden PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_mc_codigo UNIQUE (codigo_motivo)
);

-- 054. TABLA: ventas.carritos (Transaccional)
DROP TABLE IF EXISTS ventas.carritos CASCADE;
CREATE TABLE ventas.carritos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    token_sesion_carrito VARCHAR(128) NOT NULL,
    fecha_ultima_actividad TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_carr_fua DEFAULT CURRENT_TIMESTAMP,
    convertido_a_orden BOOLEAN NOT NULL CONSTRAINT DF_ventas_carr_conv DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_carr_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_carr_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_carritos PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_carr_token UNIQUE (token_sesion_carrito),
    CONSTRAINT FK_ventas_carr_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID));

-- 055. TABLA: ventas.items_carrito (Transaccional)
DROP TABLE IF EXISTS ventas.items_carrito CASCADE;
CREATE TABLE ventas.items_carrito (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_carrito BIGINT NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    cantidad INT NOT NULL CONSTRAINT CK_ventas_ic_cant CHECK (cantidad >= 1),
    precio_unitario_capturado DECIMAL(12,2) NOT NULL,
    fecha_agregado TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_ic_fa DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_ic_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_ic_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_items_carrito PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_ic_carrito_sku UNIQUE (ID_carrito, ID_variante_sku),
    CONSTRAINT FK_ventas_ic_carrito FOREIGN KEY (ID_carrito) REFERENCES ventas.carritos(ID),
    CONSTRAINT FK_ventas_ic_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 056. TABLA: ventas.carritos_abandonados_seguimiento (Transaccional Marketing)
DROP TABLE IF EXISTS ventas.carritos_abandonados_seguimiento CASCADE;
CREATE TABLE ventas.carritos_abandonados_seguimiento (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_carrito BIGINT NOT NULL,
    correo_recordatorio_enviado BOOLEAN NOT NULL CONSTRAINT DF_ventas_cas_correo DEFAULT FALSE,
    fecha_envio_recordatorio TIMESTAMP(3) NULL,
    recuperado BOOLEAN NOT NULL CONSTRAINT DF_ventas_cas_recup DEFAULT FALSE,
    monto_estimado_recuperable DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_cas_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_cas_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_carritos_abandonados PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_cas_carrito UNIQUE (ID_carrito),
    CONSTRAINT FK_ventas_cas_carrito FOREIGN KEY (ID_carrito) REFERENCES ventas.carritos(ID));

-- 057. TABLA: ventas.planes_suscripcion (Maestra Beauty Box / Resurtido Dermocosmético)
DROP TABLE IF EXISTS ventas.planes_suscripcion CASCADE;
CREATE TABLE ventas.planes_suscripcion (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_plan VARCHAR(30) NOT NULL,
    nombre_plan VARCHAR(100) NOT NULL, -- Ej: Beauty Box Salud Piel, Resurtido Sérums Ácido Hialurónico
    descripcion VARCHAR(300) NOT NULL,
    precio_recurrente_base DECIMAL(12,2) NOT NULL CONSTRAINT CK_ventas_ps_precio CHECK (precio_recurrente_base > 0),
    descuento_porcentual_fidelidad DECIMAL(5,2) NOT NULL CONSTRAINT DF_ventas_ps_desc DEFAULT 10.00,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_ps_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_ps_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_planes_suscripcion PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_ps_codigo UNIQUE (codigo_plan)
);

-- 058. TABLA: ventas.frecuencias_suscripcion (Catálogo 12)
DROP TABLE IF EXISTS ventas.frecuencias_suscripcion CASCADE;
CREATE TABLE ventas.frecuencias_suscripcion (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_frecuencia VARCHAR(20) NOT NULL,
    nombre VARCHAR(50) NOT NULL, -- Mensual, Bimestral, Trimestral
    intervalo_dias INT NOT NULL CONSTRAINT CK_ventas_fs_dias CHECK (intervalo_dias BETWEEN 15 AND 180),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_fs_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_fs_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_frecuencias_suscripcion PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_fs_codigo UNIQUE (codigo_frecuencia)
);

-- 059. TABLA: ventas.suscripciones_cliente (Transaccional)
DROP TABLE IF EXISTS ventas.suscripciones_cliente CASCADE;
CREATE TABLE ventas.suscripciones_cliente (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_suscripcion VARCHAR(35) NOT NULL,
    ID_cliente BIGINT NOT NULL,
    ID_plan_suscripcion BIGINT NOT NULL,
    ID_frecuencia_suscripcion BIGINT NOT NULL,
    ID_direccion_entrega BIGINT NOT NULL,
    ID_metodo_tokenizado BIGINT NOT NULL,
    fecha_inicio DATE NOT NULL,
    proxima_fecha_cobro DATE NOT NULL,
    estado_suscripcion VARCHAR(20) NOT NULL CONSTRAINT CK_ventas_sc_est CHECK (estado_suscripcion IN ('ACTIVA', 'PAUSADA', 'CANCELADA', 'PAGO_FALLIDO')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_sc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_sc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_suscripciones_cliente PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_sc_folio UNIQUE (folio_suscripcion),
    CONSTRAINT FK_ventas_sc_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID),
    CONSTRAINT FK_ventas_sc_plan FOREIGN KEY (ID_plan_suscripcion) REFERENCES ventas.planes_suscripcion(ID),
    CONSTRAINT FK_ventas_sc_frecuencia FOREIGN KEY (ID_frecuencia_suscripcion) REFERENCES ventas.frecuencias_suscripcion(ID),
    CONSTRAINT FK_ventas_sc_direccion FOREIGN KEY (ID_direccion_entrega) REFERENCES clientes.direcciones(ID),
    CONSTRAINT FK_ventas_sc_metodo FOREIGN KEY (ID_metodo_tokenizado) REFERENCES clientes.metodos_pago_tokenizados(ID));

-- 060. TABLA: ventas.suscripciones_items (Intermedia N:M)
DROP TABLE IF EXISTS ventas.suscripciones_items CASCADE;
CREATE TABLE ventas.suscripciones_items (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_suscripcion_cliente BIGINT NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    cantidad INT NOT NULL CONSTRAINT CK_ventas_si_cant CHECK (cantidad >= 1),
    precio_congelado_suscripcion DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_si_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_si_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_suscripciones_items PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_si_susc_sku UNIQUE (ID_suscripcion_cliente, ID_variante_sku),
    CONSTRAINT FK_ventas_si_suscripcion FOREIGN KEY (ID_suscripcion_cliente) REFERENCES ventas.suscripciones_cliente(ID),
    CONSTRAINT FK_ventas_si_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 061. TABLA: ventas.suscripciones_calendario_entregas (Transaccional)
DROP TABLE IF EXISTS ventas.suscripciones_calendario_entregas CASCADE;
CREATE TABLE ventas.suscripciones_calendario_entregas (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_suscripcion_cliente BIGINT NOT NULL,
    fecha_programada_despacho DATE NOT NULL,
    numero_ciclo_periodo INT NOT NULL,
    estado_despacho VARCHAR(30) NOT NULL CONSTRAINT CK_ventas_sce_est CHECK (estado_despacho IN ('PROGRAMADO', 'COBRADO_PROCESANDO', 'DESPACHADO', 'OMITIDO_POR_CLIENTE')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_sce_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_sce_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_suscripciones_cal PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_sce_susc_ciclo UNIQUE (ID_suscripcion_cliente, numero_ciclo_periodo),
    CONSTRAINT FK_ventas_sce_suscripcion FOREIGN KEY (ID_suscripcion_cliente) REFERENCES ventas.suscripciones_cliente(ID));

-- 062. TABLA: ventas.suscripciones_bitacora_estados (Bitácora)
DROP TABLE IF EXISTS ventas.suscripciones_bitacora_estados CASCADE;
CREATE TABLE ventas.suscripciones_bitacora_estados (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_suscripcion_cliente BIGINT NOT NULL,
    estado_anterior VARCHAR(20) NOT NULL,
    estado_nuevo VARCHAR(20) NOT NULL,
    motivo_cambio VARCHAR(255) NOT NULL,
    fecha_cambio TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_sbe_fcamb DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_sbe_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_sbe_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_suscripciones_bitacora PRIMARY KEY (ID),
    CONSTRAINT FK_ventas_sbe_suscripcion FOREIGN KEY (ID_suscripcion_cliente) REFERENCES ventas.suscripciones_cliente(ID));

-- 063. TABLA: ventas.regalos_por_compra_gwp (Transaccional Gift With Purchase)
DROP TABLE IF EXISTS ventas.regalos_por_compra_gwp CASCADE;
CREATE TABLE ventas.regalos_por_compra_gwp (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_promocion_gwp VARCHAR(30) NOT NULL,
    nombre_promocion VARCHAR(100) NOT NULL, -- Ej: Muestra de Sérum Gratis en compras > $899
    monto_minimo_requerido DECIMAL(12,2) NOT NULL,
    ID_variante_sku_regalo BIGINT NOT NULL,
    fecha_inicio TIMESTAMP(3) NOT NULL,
    fecha_fin TIMESTAMP(3) NOT NULL,
    stock_maximo_regalos INT NOT NULL,
    regalos_entregados INT NOT NULL CONSTRAINT DF_ventas_gwp_entregados DEFAULT 0,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_gwp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_gwp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_regalos_gwp PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_gwp_codigo UNIQUE (codigo_promocion_gwp),
    CONSTRAINT FK_ventas_gwp_sku FOREIGN KEY (ID_variante_sku_regalo) REFERENCES catalogo.variantes_sku(ID));

-- =================================================================================================
-- SECCIÓN 2.2: MOTOR TRANSACCIONAL DE ÓRDENES Y CHECKOUT (TABLAS 064 - 073)
-- =================================================================================================

-- 064. TABLA: ventas.ordenes (Maestra Transaccional de Ventas)
DROP TABLE IF EXISTS ventas.ordenes CASCADE;
CREATE TABLE ventas.ordenes (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_orden VARCHAR(40) NOT NULL,
    ID_cliente BIGINT NOT NULL,
    ID_estado_orden BIGINT NOT NULL,
    ID_motivo_cancelacion BIGINT NULL,
    ID_direccion_envio BIGINT NOT NULL,
    ID_direccion_facturacion BIGINT NULL,
    fecha_orden TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_ord_fo DEFAULT CURRENT_TIMESTAMP,
    subtotal_bruto DECIMAL(12,2) NOT NULL CONSTRAINT CK_ventas_ord_sub CHECK (subtotal_bruto >= 0),
    total_descuentos DECIMAL(12,2) NOT NULL CONSTRAINT DF_ventas_ord_desc DEFAULT 0.00,
    total_impuestos_iva DECIMAL(12,2) NOT NULL CONSTRAINT CK_ventas_ord_iva CHECK (total_impuestos_iva >= 0),
    costo_envio DECIMAL(12,2) NOT NULL CONSTRAINT DF_ventas_ord_envio DEFAULT 0.00,
    total_neto DECIMAL(12,2) NOT NULL CONSTRAINT CK_ventas_ord_total CHECK (total_neto > 0),
    moneda VARCHAR(3) NOT NULL CONSTRAINT DF_ventas_ord_moneda DEFAULT 'MXN',
    requiere_factura BOOLEAN NOT NULL CONSTRAINT DF_ventas_ord_rf DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_ord_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_ord_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_ordenes PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_ord_folio UNIQUE (folio_orden),
    CONSTRAINT FK_ventas_ord_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID),
    CONSTRAINT FK_ventas_ord_estado FOREIGN KEY (ID_estado_orden) REFERENCES ventas.estados_orden(ID),
    CONSTRAINT FK_ventas_ord_direnvio FOREIGN KEY (ID_direccion_envio) REFERENCES clientes.direcciones(ID),
    CONSTRAINT FK_ventas_ord_dirfact FOREIGN KEY (ID_direccion_facturacion) REFERENCES clientes.direcciones(ID),
    CONSTRAINT FK_ventas_ord_motivo_cancel FOREIGN KEY (ID_motivo_cancelacion) REFERENCES ventas.motivos_cancelacion_orden(ID));

-- 065. TABLA: ventas.ordenes_detalles (Transaccional Líneas de Producto)
DROP TABLE IF EXISTS ventas.ordenes_detalles CASCADE;
CREATE TABLE ventas.ordenes_detalles (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_orden BIGINT NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    numero_partida INT NOT NULL,
    cantidad_comprada INT NOT NULL CONSTRAINT CK_ventas_od_cant CHECK (cantidad_comprada >= 1),
    precio_unitario_venta DECIMAL(12,2) NOT NULL,
    costo_unitario_historico DECIMAL(12,2) NOT NULL,
    monto_descuento_aplicado DECIMAL(12,2) NOT NULL CONSTRAINT DF_ventas_od_desc DEFAULT 0.00,
    subtotal_linea DECIMAL(12,2) NOT NULL,
    tasa_iva_porcentual DECIMAL(5,2) NOT NULL CONSTRAINT DF_ventas_od_tasa DEFAULT 16.00,
    monto_iva_linea DECIMAL(12,2) NOT NULL,
    total_linea DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_od_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_od_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_ordenes_detalles PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_od_partida UNIQUE (ID_orden, numero_partida),
    CONSTRAINT FK_ventas_od_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID),
    CONSTRAINT FK_ventas_od_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 066. TABLA: ventas.ordenes_historial_estados (Bitácora de Estados)
DROP TABLE IF EXISTS ventas.ordenes_historial_estados CASCADE;
CREATE TABLE ventas.ordenes_historial_estados (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_orden BIGINT NOT NULL,
    ID_estado_orden BIGINT NOT NULL,
    comentario_operativo VARCHAR(300) NOT NULL,
    fecha_registro TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_ohe_fr DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_ohe_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_ohe_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_ordenes_historial PRIMARY KEY (ID),
    CONSTRAINT FK_ventas_ohe_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID),
    CONSTRAINT FK_ventas_ohe_estado FOREIGN KEY (ID_estado_orden) REFERENCES ventas.estados_orden(ID));

-- 067. TABLA: ventas.ordenes_splits_almacen (Transaccional División por Almacén)
DROP TABLE IF EXISTS ventas.ordenes_splits_almacen CASCADE;
CREATE TABLE ventas.ordenes_splits_almacen (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_orden BIGINT NOT NULL,
    sub_folio_split VARCHAR(45) NOT NULL, -- Ej: ORD-9921-A (CEDIS Norte), ORD-9921-B (CEDIS Centro)
    estado_split VARCHAR(30) NOT NULL CONSTRAINT CK_ventas_osa_est CHECK (estado_split IN ('PENDIENTE', 'ASIGNADO', 'SURTIENDO', 'EMPAQUETADO', 'EN_RUTA')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_osa_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_osa_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_ordenes_splits PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_osa_subfolio UNIQUE (sub_folio_split),
    CONSTRAINT FK_ventas_osa_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID));

-- 068. TABLA: ventas.ordenes_impuestos (Transaccional Desglose SAT)
DROP TABLE IF EXISTS ventas.ordenes_impuestos CASCADE;
CREATE TABLE ventas.ordenes_impuestos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_orden BIGINT NOT NULL,
    tipo_impuesto VARCHAR(10) NOT NULL CONSTRAINT CK_ventas_oi_tipo CHECK (tipo_impuesto IN ('002_IVA', '003_IEPS')),
    tasa_o_cuota DECIMAL(6,4) NOT NULL,
    base_gravable DECIMAL(12,2) NOT NULL,
    importe_impuesto DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_oi_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_oi_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_ordenes_impuestos PRIMARY KEY (ID),
    CONSTRAINT FK_ventas_oi_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID));

-- 069. TABLA: ventas.ordenes_descuentos (Transaccional)
DROP TABLE IF EXISTS ventas.ordenes_descuentos CASCADE;
CREATE TABLE ventas.ordenes_descuentos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_orden BIGINT NOT NULL,
    ID_tipo_descuento BIGINT NOT NULL,
    codigo_promocion_aplicado VARCHAR(40) NOT NULL,
    monto_descontado DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_odesc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_odesc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_ordenes_descuentos PRIMARY KEY (ID),
    CONSTRAINT FK_ventas_odesc_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID),
    CONSTRAINT FK_ventas_odesc_tipo FOREIGN KEY (ID_tipo_descuento) REFERENCES ventas.tipos_descuento(ID));

-- 070. TABLA: ventas.ordenes_notas_instrucciones (Transaccional)
DROP TABLE IF EXISTS ventas.ordenes_notas_instrucciones CASCADE;
CREATE TABLE ventas.ordenes_notas_instrucciones (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_orden BIGINT NOT NULL,
    es_para_regalo BOOLEAN NOT NULL CONSTRAINT DF_ventas_oni_regalo DEFAULT FALSE,
    mensaje_tarjeta_regalo VARCHAR(300) NULL,
    instrucciones_entrega_repartidor VARCHAR(300) NULL,
    empaque_especial_ecologico BOOLEAN NOT NULL CONSTRAINT DF_ventas_oni_eco DEFAULT TRUE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_oni_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_oni_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_ordenes_notas PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_oni_orden UNIQUE (ID_orden),
    CONSTRAINT FK_ventas_oni_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID));

-- 071. TABLA: ventas.reservas_temporales_stock (Transaccional Bloqueo Concurrente)
DROP TABLE IF EXISTS ventas.reservas_temporales_stock CASCADE;
CREATE TABLE ventas.reservas_temporales_stock (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_carrito BIGINT NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    cantidad_reservada INT NOT NULL CONSTRAINT CK_ventas_rts_cant CHECK (cantidad_reservada >= 1),
    fecha_reserva TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_rts_fres DEFAULT CURRENT_TIMESTAMP,
    fecha_expiracion_reserva TIMESTAMP(3) NOT NULL, -- 15 minutos para completar pago
    liberada BOOLEAN NOT NULL CONSTRAINT DF_ventas_rts_lib DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_rts_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_rts_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_reservas_stock PRIMARY KEY (ID),
    CONSTRAINT FK_ventas_rts_carrito FOREIGN KEY (ID_carrito) REFERENCES ventas.carritos(ID),
    CONSTRAINT FK_ventas_rts_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 072. TABLA: ventas.afiliados_influencers (Maestra Programa de Creadores)
DROP TABLE IF EXISTS ventas.afiliados_influencers CASCADE;
CREATE TABLE ventas.afiliados_influencers (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_afiliado VARCHAR(30) NOT NULL,
    ID_usuario BIGINT NOT NULL,
    nombre_canal_red_social VARCHAR(100) NOT NULL,
    porcentaje_comision DECIMAL(5,2) NOT NULL CONSTRAINT CK_ventas_ai_com CHECK (porcentaje_comision BETWEEN 1.00 AND 30.00),
    clabe_interbancaria VARCHAR(18) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_ai_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_ai_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_afiliados PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_ai_codigo UNIQUE (codigo_afiliado),
    CONSTRAINT FK_ventas_ai_usuario FOREIGN KEY (ID_usuario) REFERENCES seguridad.usuarios(ID));

-- 073. TABLA: ventas.comisiones_afiliados (Transaccional)
DROP TABLE IF EXISTS ventas.comisiones_afiliados CASCADE;
CREATE TABLE ventas.comisiones_afiliados (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_afiliado BIGINT NOT NULL,
    ID_orden BIGINT NOT NULL,
    monto_base_calculo DECIMAL(12,2) NOT NULL,
    monto_comision DECIMAL(12,2) NOT NULL,
    estado_pago VARCHAR(20) NOT NULL CONSTRAINT CK_ventas_ca_est CHECK (estado_pago IN ('PENDIENTE', 'APROBADA', 'PAGADA', 'CANCELADA_POR_DEVOLUCION')),
    fecha_dispersion_pago TIMESTAMP(3) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_ventas_ca_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_ventas_ca_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_ventas_comisiones PRIMARY KEY (ID),
    CONSTRAINT UQ_ventas_ca_orden UNIQUE (ID_orden),
    CONSTRAINT FK_ventas_ca_afiliado FOREIGN KEY (ID_afiliado) REFERENCES ventas.afiliados_influencers(ID),
    CONSTRAINT FK_ventas_ca_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID));

-- =================================================================================================
-- SECCIÓN 2.3: PASARELAS DE PAGO, WALLET, ANTIFRAUDE Y REEMBOLSOS (TABLAS 074 - 086)
-- =================================================================================================

-- 074. TABLA: pagos.proveedores_pasarela (Catálogo 13)
DROP TABLE IF EXISTS pagos.proveedores_pasarela CASCADE;
CREATE TABLE pagos.proveedores_pasarela (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_pasarela VARCHAR(20) NOT NULL,
    nombre_comercial VARCHAR(60) NOT NULL, -- STRIPE, MERCADOPAGO, PAYPAL, OPENPAY, SPEI_DIRECTO
    url_webhook VARCHAR(250) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_pp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_pp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_proveedores_pasarela PRIMARY KEY (ID),
    CONSTRAINT UQ_pagos_pp_codigo UNIQUE (codigo_pasarela)
);

-- 075. TABLA: pagos.metodos_pago (Catálogo 14)
DROP TABLE IF EXISTS pagos.metodos_pago CASCADE;
CREATE TABLE pagos.metodos_pago (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_metodo VARCHAR(20) NOT NULL,
    nombre_metodo VARCHAR(60) NOT NULL, -- TARJETA_CREDITO, TARJETA_DEBITO, TRANSFERENCIA_SPEI, BILLETERA_WALLET, PUNTOS_BEAUTY
    comision_porcentual_fija DECIMAL(5,2) NOT NULL CONSTRAINT DF_pagos_mp_comfija DEFAULT 2.90,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_mp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_mp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_metodos_pago PRIMARY KEY (ID),
    CONSTRAINT UQ_pagos_mp_codigo UNIQUE (codigo_metodo)
);

-- 076. TABLA: pagos.transacciones (Maestra Transaccional de Pagos)
DROP TABLE IF EXISTS pagos.transacciones CASCADE;
CREATE TABLE pagos.transacciones (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_transaccion VARCHAR(45) NOT NULL,
    ID_orden BIGINT NOT NULL,
    ID_proveedor_pasarela BIGINT NOT NULL,
    ID_metodo_pago BIGINT NOT NULL,
    id_transaccion_externa_pasarela VARCHAR(100) NOT NULL, -- ID devuelto por Stripe/MercadoPago
    monto_transaccion DECIMAL(12,2) NOT NULL CONSTRAINT CK_pagos_tx_monto CHECK (monto_transaccion > 0),
    moneda VARCHAR(3) NOT NULL CONSTRAINT DF_pagos_tx_mon DEFAULT 'MXN',
    estado_pago VARCHAR(20) NOT NULL CONSTRAINT CK_pagos_tx_est CHECK (estado_pago IN ('PENDIENTE', 'APROBADA', 'RECHAZADA', 'CANCELADA', 'EN_MEDIACION')),
    codigo_autorizacion_bancaria VARCHAR(30) NULL,
    fecha_pago_efectuado TIMESTAMP(3) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_tx_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_tx_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_transacciones PRIMARY KEY (ID),
    CONSTRAINT UQ_pagos_tx_folio UNIQUE (folio_transaccion),
    CONSTRAINT FK_pagos_tx_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID),
    CONSTRAINT FK_pagos_tx_pasarela FOREIGN KEY (ID_proveedor_pasarela) REFERENCES pagos.proveedores_pasarela(ID),
    CONSTRAINT FK_pagos_tx_metodo FOREIGN KEY (ID_metodo_pago) REFERENCES pagos.metodos_pago(ID));

-- 077. TABLA: pagos.intentos_cobro (Bitácora de Comunicación de API Pasarelas)
DROP TABLE IF EXISTS pagos.intentos_cobro CASCADE;
CREATE TABLE pagos.intentos_cobro (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_transaccion BIGINT NOT NULL,
    numero_intento INT NOT NULL,
    codigo_respuesta_http INT NOT NULL,
    payload_solicitud_sanitizado TEXT NOT NULL, -- Sin CVV ni datos sensibles
    payload_respuesta_pasarela TEXT NOT NULL,
    mensaje_error_banco VARCHAR(250) NULL,
    fecha_intento TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_ic_fi DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_ic_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_ic_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_intentos_cobro PRIMARY KEY (ID),
    CONSTRAINT FK_pagos_ic_transaccion FOREIGN KEY (ID_transaccion) REFERENCES pagos.transacciones(ID));

-- 078. TABLA: pagos.split_multipagos (Transaccional Multipago)
DROP TABLE IF EXISTS pagos.split_multipagos CASCADE;
CREATE TABLE pagos.split_multipagos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_orden BIGINT NOT NULL,
    ID_metodo_pago BIGINT NOT NULL,
    monto_asignado DECIMAL(12,2) NOT NULL,
    referencia_comprobante VARCHAR(80) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_smp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_smp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_split_multipagos PRIMARY KEY (ID),
    CONSTRAINT FK_pagos_smp_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID),
    CONSTRAINT FK_pagos_smp_metodo FOREIGN KEY (ID_metodo_pago) REFERENCES pagos.metodos_pago(ID));

-- 079. TABLA: pagos.billetera_electronica (Maestra Wallet Cliente)
DROP TABLE IF EXISTS pagos.billetera_electronica CASCADE;
CREATE TABLE pagos.billetera_electronica (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    saldo_disponible DECIMAL(12,2) NOT NULL CONSTRAINT DF_pagos_be_saldo DEFAULT 0.00,
    saldo_bloqueado_retenido DECIMAL(12,2) NOT NULL CONSTRAINT DF_pagos_be_bloq DEFAULT 0.00,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_be_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_be_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_billetera PRIMARY KEY (ID),
    CONSTRAINT UQ_pagos_be_cliente UNIQUE (ID_cliente),
    CONSTRAINT FK_pagos_be_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID));

-- 080. TABLA: pagos.movimientos_billetera (Transaccional)
DROP TABLE IF EXISTS pagos.movimientos_billetera CASCADE;
CREATE TABLE pagos.movimientos_billetera (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_billetera BIGINT NOT NULL,
    tipo_movimiento VARCHAR(20) NOT NULL CONSTRAINT CK_pagos_mb_tipo CHECK (tipo_movimiento IN ('CARGA_SALDO', 'PAGO_ORDEN', 'REEMBOLSO_DEVOLUCION', 'BONIFICACION_FIDELIDAD')),
    monto DECIMAL(12,2) NOT NULL CONSTRAINT CK_pagos_mb_monto CHECK (monto > 0),
    saldo_anterior DECIMAL(12,2) NOT NULL,
    saldo_posterior DECIMAL(12,2) NOT NULL,
    descripcion_motivo VARCHAR(200) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_mb_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_mb_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_movimientos_billetera PRIMARY KEY (ID),
    CONSTRAINT FK_pagos_mb_billetera FOREIGN KEY (ID_billetera) REFERENCES pagos.billetera_electronica(ID));

-- 081. TABLA: pagos.tarjetas_regalo_giftcards (Maestra)
DROP TABLE IF EXISTS pagos.tarjetas_regalo_giftcards CASCADE;
CREATE TABLE pagos.tarjetas_regalo_giftcards (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_giftcard_hash VARCHAR(128) NOT NULL,
    monto_inicial DECIMAL(12,2) NOT NULL CONSTRAINT CK_pagos_gc_ini CHECK (monto_inicial > 0),
    saldo_actual DECIMAL(12,2) NOT NULL CONSTRAINT CK_pagos_gc_saldo CHECK (saldo_actual >= 0),
    fecha_vencimiento DATE NOT NULL,
    ID_cliente_comprador BIGINT NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_gc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_gc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_giftcards PRIMARY KEY (ID),
    CONSTRAINT UQ_pagos_gc_hash UNIQUE (codigo_giftcard_hash),
    CONSTRAINT FK_pagos_gc_comprador FOREIGN KEY (ID_cliente_comprador) REFERENCES clientes.clientes(ID));

-- 082. TABLA: pagos.redenciones_giftcards (Transaccional)
DROP TABLE IF EXISTS pagos.redenciones_giftcards CASCADE;
CREATE TABLE pagos.redenciones_giftcards (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_giftcard BIGINT NOT NULL,
    ID_orden BIGINT NOT NULL,
    monto_redimido DECIMAL(12,2) NOT NULL CONSTRAINT CK_pagos_rg_monto CHECK (monto_redimido > 0),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_rg_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_rg_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_redenciones_giftcard PRIMARY KEY (ID),
    CONSTRAINT FK_pagos_rg_giftcard FOREIGN KEY (ID_giftcard) REFERENCES pagos.tarjetas_regalo_giftcards(ID),
    CONSTRAINT FK_pagos_rg_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID));

-- 083. TABLA: pagos.reglas_antifraude (Maestra)
DROP TABLE IF EXISTS pagos.reglas_antifraude CASCADE;
CREATE TABLE pagos.reglas_antifraude (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_regla VARCHAR(30) NOT NULL,
    descripcion VARCHAR(200) NOT NULL,
    puntaje_riesgo_asignado INT NOT NULL CONSTRAINT CK_pagos_ra_pts CHECK (puntaje_riesgo_asignado BETWEEN 1 AND 100),
    bloqueo_automatico BOOLEAN NOT NULL CONSTRAINT DF_pagos_ra_bloq DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_ra_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_ra_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_reglas_antifraude PRIMARY KEY (ID),
    CONSTRAINT UQ_pagos_ra_codigo UNIQUE (codigo_regla)
);

-- 084. TABLA: pagos.evaluaciones_antifraude (Transaccional)
DROP TABLE IF EXISTS pagos.evaluaciones_antifraude CASCADE;
CREATE TABLE pagos.evaluaciones_antifraude (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_orden BIGINT NOT NULL,
    ID_regla_antifraude BIGINT NULL,
    score_riesgo_total INT NOT NULL,
    nivel_riesgo VARCHAR(20) NOT NULL CONSTRAINT CK_pagos_ea_nivel CHECK (nivel_riesgo IN ('BAJO', 'MEDIO', 'ALTO_REQUERIR_3DS', 'CRITICO_RECHAZADO')),
    ip_origen VARCHAR(45) NOT NULL,
    distancia_geografica_km INT NULL,
    dispositivo_sospechoso BOOLEAN NOT NULL CONSTRAINT DF_pagos_ea_disp DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_ea_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_ea_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_evaluaciones_fraude PRIMARY KEY (ID),
    CONSTRAINT UQ_pagos_ea_orden UNIQUE (ID_orden),
    CONSTRAINT FK_pagos_ea_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID),
    CONSTRAINT FK_pagos_ea_regla FOREIGN KEY (ID_regla_antifraude) REFERENCES pagos.reglas_antifraude(ID));

-- 085. TABLA: pagos.contracargos_chargebacks (Transaccional Disputas)
DROP TABLE IF EXISTS pagos.contracargos_chargebacks CASCADE;
CREATE TABLE pagos.contracargos_chargebacks (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_transaccion BIGINT NOT NULL,
    folio_disputa_pasarela VARCHAR(60) NOT NULL,
    motivo_disputa VARCHAR(150) NOT NULL, -- Tarjeta no presente, Mercancía no recibida, No reconocida
    monto_disputado DECIMAL(12,2) NOT NULL,
    fecha_notificacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_cc_fn DEFAULT CURRENT_TIMESTAMP,
    fecha_limite_evidencia DATE NOT NULL,
    estatus_disputa VARCHAR(20) NOT NULL CONSTRAINT CK_pagos_cc_est CHECK (estatus_disputa IN ('ABIERTA', 'EN_REVISION', 'GANADA_POR_COMERCIO', 'PERDIDA_POR_COMERCIO')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_cc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_cc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_contracargos PRIMARY KEY (ID),
    CONSTRAINT UQ_pagos_cc_disputa UNIQUE (folio_disputa_pasarela),
    CONSTRAINT FK_pagos_cc_transaccion FOREIGN KEY (ID_transaccion) REFERENCES pagos.transacciones(ID));

-- 086. TABLA: pagos.reembolsos_transaccion (Transaccional)
DROP TABLE IF EXISTS pagos.reembolsos_transaccion CASCADE;
CREATE TABLE pagos.reembolsos_transaccion (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_transaccion BIGINT NOT NULL,
    folio_reembolso_pasarela VARCHAR(80) NOT NULL,
    monto_reembolsado DECIMAL(12,2) NOT NULL CONSTRAINT CK_pagos_reemb_monto CHECK (monto_reembolsado > 0),
    motivo_reembolso VARCHAR(250) NOT NULL,
    fecha_reembolso TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_reemb_fr DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_pagos_reemb_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_pagos_reemb_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_pagos_reembolsos PRIMARY KEY (ID),
    CONSTRAINT UQ_pagos_reemb_folio UNIQUE (folio_reembolso_pasarela),
    CONSTRAINT FK_pagos_reemb_transaccion FOREIGN KEY (ID_transaccion) REFERENCES pagos.transacciones(ID));

-- =================================================================================================
-- SECCIÓN 2.4: FACTURACIÓN ELECTRÓNICA CFDI 4.0 Y MOTOR DE PROMOCIONES (TABLAS 087 - 100)
-- =================================================================================================

-- 087. TABLA: fiscal.regimenes_sat (Catálogo 15)
DROP TABLE IF EXISTS fiscal.regimenes_sat CASCADE;
CREATE TABLE fiscal.regimenes_sat (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    clave_regimen_sat VARCHAR(4) NOT NULL, -- Ej: 601 General de Ley, 605 Sueldos, 612 Actividad Empresarial, 626 RESICO
    descripcion VARCHAR(200) NOT NULL,
    aplica_persona_fisica BOOLEAN NOT NULL,
    aplica_persona_moral BOOLEAN NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_fiscal_rs_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_fiscal_rs_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_fiscal_regimenes_sat PRIMARY KEY (ID),
    CONSTRAINT UQ_fiscal_rs_clave UNIQUE (clave_regimen_sat)
);

-- 088. TABLA: fiscal.usos_cfdi (Catálogo 16)
DROP TABLE IF EXISTS fiscal.usos_cfdi CASCADE;
CREATE TABLE fiscal.usos_cfdi (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    clave_uso_cfdi VARCHAR(5) NOT NULL, -- G01 Adquisición de mercancías, G03 Gastos en general, CP01 Pagos, S01 Sin efectos fiscales
    descripcion VARCHAR(150) NOT NULL,
    aplica_fisica BOOLEAN NOT NULL,
    aplica_moral BOOLEAN NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_fiscal_uc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_fiscal_uc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_fiscal_usos_cfdi PRIMARY KEY (ID),
    CONSTRAINT UQ_fiscal_uc_clave UNIQUE (clave_uso_cfdi)
);

-- 089. TABLA: fiscal.datos_fiscales_cliente (Transaccional)
DROP TABLE IF EXISTS fiscal.datos_fiscales_cliente CASCADE;
CREATE TABLE fiscal.datos_fiscales_cliente (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cliente BIGINT NOT NULL,
    rfc_emisor VARCHAR(13) NOT NULL,
    razon_social VARCHAR(150) NOT NULL,
    codigo_postal_fiscal VARCHAR(10) NOT NULL,
    ID_regimen_sat BIGINT NOT NULL,
    ID_uso_cfdi_predeterminado BIGINT NOT NULL,
    correo_envio_cfdi VARCHAR(150) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_fiscal_dfc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_fiscal_dfc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_fiscal_datos_fiscales PRIMARY KEY (ID),
    CONSTRAINT FK_fiscal_dfc_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID),
    CONSTRAINT FK_fiscal_dfc_regimen FOREIGN KEY (ID_regimen_sat) REFERENCES fiscal.regimenes_sat(ID),
    CONSTRAINT FK_fiscal_dfc_uso FOREIGN KEY (ID_uso_cfdi_predeterminado) REFERENCES fiscal.usos_cfdi(ID));

-- 090. TABLA: fiscal.facturas_cfdi (Maestra Transaccional CFDI 4.0)
DROP TABLE IF EXISTS fiscal.facturas_cfdi CASCADE;
CREATE TABLE fiscal.facturas_cfdi (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_orden BIGINT NOT NULL,
    ID_dato_fiscal BIGINT NOT NULL,
    serie_factura VARCHAR(10) NOT NULL,
    folio_factura VARCHAR(20) NOT NULL,
    uuid_sat_fiscal UUID NOT NULL, -- UUID de timbrado fiscal SAT
    sello_digital_cfdi TEXT NOT NULL,
    sello_sat TEXT NOT NULL,
    cadena_original_timbre TEXT NOT NULL,
    numero_certificado_sat VARCHAR(20) NOT NULL,
    fecha_timbrado TIMESTAMP(3) NOT NULL,
    monto_total_facturado DECIMAL(12,2) NOT NULL,
    estado_cfdi VARCHAR(20) NOT NULL CONSTRAINT CK_fiscal_fcfdi_est CHECK (estado_cfdi IN ('TIMBRADA_VIGENTE', 'CANCELADA_SAT', 'ERROR_TIMBRADO')),
    xml_comprobante_url VARCHAR(300) NOT NULL,
    pdf_representacion_url VARCHAR(300) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_fiscal_fcfdi_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_fiscal_fcfdi_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_fiscal_facturas PRIMARY KEY (ID),
    CONSTRAINT UQ_fiscal_fcfdi_uuid UNIQUE (uuid_sat_fiscal),
    CONSTRAINT FK_fiscal_fcfdi_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID),
    CONSTRAINT FK_fiscal_fcfdi_df FOREIGN KEY (ID_dato_fiscal) REFERENCES fiscal.datos_fiscales_cliente(ID));

-- 091. TABLA: fiscal.facturas_partidas (Transaccional)
DROP TABLE IF EXISTS fiscal.facturas_partidas CASCADE;
CREATE TABLE fiscal.facturas_partidas (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_factura BIGINT NOT NULL,
    clave_producto_servicio_sat VARCHAR(10) NOT NULL, -- Ej: 53131600 Cosméticos y cuidado de la piel
    clave_unidad_sat VARCHAR(5) NOT NULL, -- H87 Pieza
    cantidad DECIMAL(12,2) NOT NULL,
    valor_unitario DECIMAL(12,2) NOT NULL,
    importe_neto DECIMAL(12,2) NOT NULL,
    objeto_impuesto VARCHAR(3) NOT NULL CONSTRAINT DF_fiscal_fp_obj DEFAULT '02', -- 02 Sí objeto de impuesto
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_fiscal_fp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_fiscal_fp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_fiscal_facturas_partidas PRIMARY KEY (ID),
    CONSTRAINT FK_fiscal_fp_factura FOREIGN KEY (ID_factura) REFERENCES fiscal.facturas_cfdi(ID));

-- 092. TABLA: fiscal.complementos_pago (Transaccional Recibos Electrónicos de Pago)
DROP TABLE IF EXISTS fiscal.complementos_pago CASCADE;
CREATE TABLE fiscal.complementos_pago (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_factura BIGINT NOT NULL,
    ID_transaccion BIGINT NOT NULL,
    uuid_sat_complemento UUID NOT NULL,
    numero_parcialidad INT NOT NULL CONSTRAINT DF_fiscal_cp_parc DEFAULT 1,
    saldo_anterior DECIMAL(12,2) NOT NULL,
    monto_pagado DECIMAL(12,2) NOT NULL,
    saldo_insoluto DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_fiscal_cp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_fiscal_cp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_fiscal_complementos_pago PRIMARY KEY (ID),
    CONSTRAINT UQ_fiscal_cp_uuid UNIQUE (uuid_sat_complemento),
    CONSTRAINT FK_fiscal_cp_factura FOREIGN KEY (ID_factura) REFERENCES fiscal.facturas_cfdi(ID),
    CONSTRAINT FK_fiscal_cp_transaccion FOREIGN KEY (ID_transaccion) REFERENCES pagos.transacciones(ID));

-- 093. TABLA: fiscal.notas_credito (Transaccional)
DROP TABLE IF EXISTS fiscal.notas_credito CASCADE;
CREATE TABLE fiscal.notas_credito (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_factura BIGINT NOT NULL,
    uuid_sat_nota_credito UUID NOT NULL,
    motivo_devolucion_sat VARCHAR(3) NOT NULL, -- 01 Devolución de mercancías
    subtotal_acreditado DECIMAL(12,2) NOT NULL,
    iva_acreditado DECIMAL(12,2) NOT NULL,
    total_acreditado DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_fiscal_nc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_fiscal_nc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_fiscal_notas_credito PRIMARY KEY (ID),
    CONSTRAINT UQ_fiscal_nc_uuid UNIQUE (uuid_sat_nota_credito),
    CONSTRAINT FK_fiscal_nc_factura FOREIGN KEY (ID_factura) REFERENCES fiscal.facturas_cfdi(ID));

-- 094. TABLA: fiscal.cancelaciones_cfdi (Transaccional Auditoría Fiscal)
DROP TABLE IF EXISTS fiscal.cancelaciones_cfdi CASCADE;
CREATE TABLE fiscal.cancelaciones_cfdi (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_factura BIGINT NOT NULL,
    motivo_cancelacion_sat VARCHAR(4) NOT NULL CONSTRAINT CK_fiscal_ccfdi_mot CHECK (motivo_cancelacion_sat IN ('01', '02', '03', '04')),
    uuid_sustitucion UUID NULL,
    acuse_cancelacion_sat TEXT NOT NULL,
    fecha_solicitud_cancelacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_fiscal_ccfdi_fsol DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_fiscal_ccfdi_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_fiscal_ccfdi_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_fiscal_cancelaciones PRIMARY KEY (ID),
    CONSTRAINT FK_fiscal_ccfdi_factura FOREIGN KEY (ID_factura) REFERENCES fiscal.facturas_cfdi(ID));

-- 095. TABLA: promos.campanias (Maestra)
DROP TABLE IF EXISTS promos.campanias CASCADE;
CREATE TABLE promos.campanias (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_campania VARCHAR(30) NOT NULL,
    nombre_campania VARCHAR(100) NOT NULL, -- Ej: Hot Sale Belleza, Black Friday Dermocosmética
    fecha_inicio TIMESTAMP(3) NOT NULL,
    fecha_fin TIMESTAMP(3) NOT NULL,
    presupuesto_maximo_descuentos DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_promos_camp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_promos_camp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_promos_campanias PRIMARY KEY (ID),
    CONSTRAINT UQ_promos_camp_codigo UNIQUE (codigo_campania)
);

-- 096. TABLA: promos.cupones (Maestra Cupones)
DROP TABLE IF EXISTS promos.cupones CASCADE;
CREATE TABLE promos.cupones (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_campania BIGINT NOT NULL,
    codigo_cupon VARCHAR(30) NOT NULL, -- Ej: PIELRADIANTE20, BIENVENIDA10
    ID_tipo_descuento BIGINT NOT NULL,
    valor_descuento DECIMAL(12,2) NOT NULL CONSTRAINT CK_promos_cup_val CHECK (valor_descuento > 0),
    monto_minimo_compra DECIMAL(12,2) NOT NULL CONSTRAINT DF_promos_cup_min DEFAULT 0.00,
    limite_usos_totales INT NOT NULL,
    usos_actuales INT NOT NULL CONSTRAINT DF_promos_cup_usos DEFAULT 0,
    limite_usos_por_cliente INT NOT NULL CONSTRAINT DF_promos_cup_ucli DEFAULT 1,
    fecha_expiracion TIMESTAMP(3) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_promos_cup_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_promos_cup_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_promos_cupones PRIMARY KEY (ID),
    CONSTRAINT UQ_promos_cup_codigo UNIQUE (codigo_cupon),
    CONSTRAINT FK_promos_cup_campania FOREIGN KEY (ID_campania) REFERENCES promos.campanias(ID),
    CONSTRAINT FK_promos_cup_tipo FOREIGN KEY (ID_tipo_descuento) REFERENCES ventas.tipos_descuento(ID));

-- 097. TABLA: promos.reglas_elegibilidad_cupon (Transaccional)
DROP TABLE IF EXISTS promos.reglas_elegibilidad_cupon CASCADE;
CREATE TABLE promos.reglas_elegibilidad_cupon (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cupon BIGINT NOT NULL,
    solo_primera_compra BOOLEAN NOT NULL CONSTRAINT DF_promos_rec_pc DEFAULT FALSE,
    excluye_kits_promocionales BOOLEAN NOT NULL CONSTRAINT DF_promos_rec_ek DEFAULT TRUE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_promos_rec_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_promos_rec_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_promos_reglas_cupon PRIMARY KEY (ID),
    CONSTRAINT UQ_promos_rec_cupon UNIQUE (ID_cupon),
    CONSTRAINT FK_promos_rec_cupon FOREIGN KEY (ID_cupon) REFERENCES promos.cupones(ID));

-- 098. TABLA: promos.cupones_categorias_excluidas (Intermedia N:M)
DROP TABLE IF EXISTS promos.cupones_categorias_excluidas CASCADE;
CREATE TABLE promos.cupones_categorias_excluidas (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cupon BIGINT NOT NULL,
    ID_categoria BIGINT NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_promos_cce_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_promos_cce_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_promos_cupones_exclusiones PRIMARY KEY (ID),
    CONSTRAINT UQ_promos_cce_cupon_cat UNIQUE (ID_cupon, ID_categoria),
    CONSTRAINT FK_promos_cce_cupon FOREIGN KEY (ID_cupon) REFERENCES promos.cupones(ID),
    CONSTRAINT FK_promos_cce_categoria FOREIGN KEY (ID_categoria) REFERENCES catalogo.categorias(ID));

-- 099. TABLA: promos.redenciones_cupones (Transaccional)
DROP TABLE IF EXISTS promos.redenciones_cupones CASCADE;
CREATE TABLE promos.redenciones_cupones (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_cupon BIGINT NOT NULL,
    ID_cliente BIGINT NOT NULL,
    ID_orden BIGINT NOT NULL,
    monto_ahorrado DECIMAL(12,2) NOT NULL,
    fecha_aplicacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_promos_rcup_fa DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_promos_rcup_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_promos_rcup_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_promos_redenciones_cupones PRIMARY KEY (ID),
    CONSTRAINT FK_promos_rcup_cupon FOREIGN KEY (ID_cupon) REFERENCES promos.cupones(ID),
    CONSTRAINT FK_promos_rcup_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID),
    CONSTRAINT FK_promos_rcup_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID));

-- 100. TABLA: promos.ventas_flash_horarias (Transaccional Promociones Relámpago)
DROP TABLE IF EXISTS promos.ventas_flash_horarias CASCADE;
CREATE TABLE promos.ventas_flash_horarias (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    precio_oferta_flash DECIMAL(12,2) NOT NULL CONSTRAINT CK_promos_vfh_precio CHECK (precio_oferta_flash > 0),
    stock_destinado_flash INT NOT NULL CONSTRAINT CK_promos_vfh_stock CHECK (stock_destinado_flash >= 1),
    stock_vendido_flash INT NOT NULL CONSTRAINT DF_promos_vfh_vend DEFAULT 0,
    fecha_hora_inicio TIMESTAMP(3) NOT NULL,
    fecha_hora_fin TIMESTAMP(3) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_promos_vfh_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_promos_vfh_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_promos_ventas_flash PRIMARY KEY (ID),
    CONSTRAINT FK_promos_vfh_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- =================================================================================================
-- TECNOLÓGICO NACIONAL DE MÉXICO - INSTITUTO TECNOLÓGICO SUPERIOR DE MONCLOVA
-- PROYECTO INTEGRADOR V - INGENIERÍA INFORMÁTICA
-- SISTEMA E-COMMERCE DE CUIDADO DE LA SALUD, BELLEZA Y MAQUILLAJE
-- =================================================================================================
-- SUBMÓDULO 3: CADENA DE SUMINISTRO, LOTES SANITARIOS, WMS, ENVIOS, RMA Y AUDITORÍA FORENSE
-- AUTOR / INTEGRANTE 3: Estudiante 3 (Responsable de Tablas 101 a 150)
-- SGBD DESTINO: PostgreSQL 12+
-- TOTAL DE TABLAS EN ESTE SCRIPT: 50 Tablas Normalizadas (1FN, 2FN, 3FN, BCNF, 4FN)
-- CRITERIO DE AUDITORÍA: Cada tabla implementa ID autoincrementable y las 7 columnas de trazabilidad
-- y borrado lógico (Soft Delete) conforme a la LFPDPPP y Código Penal Federal.
-- =================================================================================================


-- Crear esquemas lógicos para el submódulo de cadena de suministro, almacenes, logística y auditoría
CREATE SCHEMA IF NOT EXISTS compras;
CREATE SCHEMA IF NOT EXISTS wms;
CREATE SCHEMA IF NOT EXISTS envios;
CREATE SCHEMA IF NOT EXISTS postventa;
CREATE SCHEMA IF NOT EXISTS auditoria;
CREATE SCHEMA IF NOT EXISTS sistema;

-- =================================================================================================
-- SECCIÓN 3.1: COMPRAS, PROVEEDORES Y RECEPCIÓN SANITARIA (TABLAS 101 - 112)
-- =================================================================================================

-- 101. TABLA: compras.estados_orden_compra (Catálogo 17)
DROP TABLE IF EXISTS compras.estados_orden_compra CASCADE;
CREATE TABLE compras.estados_orden_compra (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_estado VARCHAR(20) NOT NULL,
    nombre_estado VARCHAR(50) NOT NULL, -- BORRADOR, AUTORIZADA, ENVIADA_PROVEEDOR, RECIBIDA_PARCIAL, RECIBIDA_TOTAL, CANCELADA
    descripcion VARCHAR(200) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_eoc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_eoc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_estados_oc PRIMARY KEY (ID),
    CONSTRAINT UQ_compras_eoc_codigo UNIQUE (codigo_estado)
);

-- 102. TABLA: compras.proveedores (Maestra)
DROP TABLE IF EXISTS compras.proveedores CASCADE;
CREATE TABLE compras.proveedores (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_proveedor VARCHAR(30) NOT NULL,
    razon_social VARCHAR(150) NOT NULL,
    nombre_comercial VARCHAR(120) NOT NULL,
    rfc_proveedor VARCHAR(13) NOT NULL,
    pais_origen VARCHAR(60) NOT NULL,
    dias_credito_pago INT NOT NULL CONSTRAINT DF_compras_prov_cred DEFAULT 30,
    calificacion_calidad_sanitaria DECIMAL(3,2) NOT NULL CONSTRAINT DF_compras_prov_calif DEFAULT 5.00,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_prov_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_prov_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_proveedores PRIMARY KEY (ID),
    CONSTRAINT UQ_compras_prov_codigo UNIQUE (codigo_proveedor),
    CONSTRAINT UQ_compras_prov_rfc UNIQUE (rfc_proveedor)
);

-- 103. TABLA: compras.contactos_proveedor (Transaccional)
DROP TABLE IF EXISTS compras.contactos_proveedor CASCADE;
CREATE TABLE compras.contactos_proveedor (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_proveedor BIGINT NOT NULL,
    nombre_contacto VARCHAR(100) NOT NULL,
    puesto_cargo VARCHAR(80) NOT NULL,
    email_contacto VARCHAR(150) NOT NULL,
    telefono_directo VARCHAR(20) NOT NULL,
    es_contacto_principal BOOLEAN NOT NULL CONSTRAINT DF_compras_cp_princ DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_cp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_cp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_contactos_prov PRIMARY KEY (ID),
    CONSTRAINT FK_compras_cp_proveedor FOREIGN KEY (ID_proveedor) REFERENCES compras.proveedores(ID));

-- 104. TABLA: compras.proveedor_slas (Transaccional Acuerdos de Nivel de Servicio)
DROP TABLE IF EXISTS compras.proveedor_slas CASCADE;
CREATE TABLE compras.proveedor_slas (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_proveedor BIGINT NOT NULL,
    tiempo_promedio_entrega_dias INT NOT NULL CONSTRAINT CK_compras_sla_dias CHECK (tiempo_promedio_entrega_dias >= 1),
    porcentaje_tolerancia_mermas DECIMAL(4,2) NOT NULL CONSTRAINT DF_compras_sla_mermas DEFAULT 0.50,
    penalizacion_por_dia_retraso_porc DECIMAL(4,2) NOT NULL CONSTRAINT DF_compras_sla_penal DEFAULT 1.00,
    vigencia_acuerdo_fin DATE NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_sla_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_sla_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_slas PRIMARY KEY (ID),
    CONSTRAINT FK_compras_sla_proveedor FOREIGN KEY (ID_proveedor) REFERENCES compras.proveedores(ID));

-- 105. TABLA: compras.proveedor_productos (Intermedia N:M Catálogo de Precios de Compra)
DROP TABLE IF EXISTS compras.proveedor_productos CASCADE;
CREATE TABLE compras.proveedor_productos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_proveedor BIGINT NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    codigo_articulo_proveedor VARCHAR(50) NOT NULL,
    costo_negociado_unitario DECIMAL(12,2) NOT NULL CONSTRAINT CK_compras_pp_costo CHECK (costo_negociado_unitario > 0),
    lote_minimo_compra INT NOT NULL CONSTRAINT DF_compras_pp_lmin DEFAULT 1,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_pp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_pp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_proveedor_sku PRIMARY KEY (ID),
    CONSTRAINT UQ_compras_pp_prov_sku UNIQUE (ID_proveedor, ID_variante_sku),
    CONSTRAINT FK_compras_pp_proveedor FOREIGN KEY (ID_proveedor) REFERENCES compras.proveedores(ID),
    CONSTRAINT FK_compras_pp_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 106. TABLA: compras.requisiciones (Transaccional Requisiciones Internas)
DROP TABLE IF EXISTS compras.requisiciones CASCADE;
CREATE TABLE compras.requisiciones (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_requisicion VARCHAR(35) NOT NULL,
    departamento_solicitante VARCHAR(80) NOT NULL, -- Ej: Almacén WMS Resurtido, Dermocosmética
    prioridad VARCHAR(20) NOT NULL CONSTRAINT CK_compras_req_prio CHECK (prioridad IN ('BAJA', 'MEDIA', 'URGENTE_DESABASTO')),
    motivo_solicitud VARCHAR(300) NOT NULL,
    fecha_limite_requerida DATE NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_req_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_req_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_requisiciones PRIMARY KEY (ID),
    CONSTRAINT UQ_compras_req_folio UNIQUE (folio_requisicion)
);

-- 107. TABLA: compras.requisiciones_detalles (Transaccional)
DROP TABLE IF EXISTS compras.requisiciones_detalles CASCADE;
CREATE TABLE compras.requisiciones_detalles (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_requisicion BIGINT NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    cantidad_requerida INT NOT NULL CONSTRAINT CK_compras_rd_cant CHECK (cantidad_requerida >= 1),
    cantidad_aprobada INT NOT NULL CONSTRAINT DF_compras_rd_aprob DEFAULT 0,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_rd_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_rd_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_requisiciones_det PRIMARY KEY (ID),
    CONSTRAINT UQ_compras_rd_req_sku UNIQUE (ID_requisicion, ID_variante_sku),
    CONSTRAINT FK_compras_rd_requisicion FOREIGN KEY (ID_requisicion) REFERENCES compras.requisiciones(ID),
    CONSTRAINT FK_compras_rd_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 108. TABLA: compras.ordenes_compra (Maestra Órdenes de Compra a Proveedores)
DROP TABLE IF EXISTS compras.ordenes_compra CASCADE;
CREATE TABLE compras.ordenes_compra (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_orden_compra VARCHAR(35) NOT NULL,
    ID_proveedor BIGINT NOT NULL,
    ID_estado_oc BIGINT NOT NULL,
    fecha_emision TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_oc_fe DEFAULT CURRENT_TIMESTAMP,
    fecha_entrega_esperada DATE NOT NULL,
    subtotal DECIMAL(12,2) NOT NULL,
    total_iva DECIMAL(12,2) NOT NULL,
    total_orden_compra DECIMAL(12,2) NOT NULL,
    condiciones_pago VARCHAR(150) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_oc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_oc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_ordenes_compra PRIMARY KEY (ID),
    CONSTRAINT UQ_compras_oc_folio UNIQUE (folio_orden_compra),
    CONSTRAINT FK_compras_oc_proveedor FOREIGN KEY (ID_proveedor) REFERENCES compras.proveedores(ID),
    CONSTRAINT FK_compras_oc_estado FOREIGN KEY (ID_estado_oc) REFERENCES compras.estados_orden_compra(ID));

-- 109. TABLA: compras.ordenes_compra_detalles (Transaccional)
DROP TABLE IF EXISTS compras.ordenes_compra_detalles CASCADE;
CREATE TABLE compras.ordenes_compra_detalles (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_orden_compra BIGINT NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    cantidad_pedida INT NOT NULL CONSTRAINT CK_compras_ocd_cp CHECK (cantidad_pedida >= 1),
    cantidad_recibida INT NOT NULL CONSTRAINT DF_compras_ocd_cr DEFAULT 0,
    costo_unitario_compra DECIMAL(12,2) NOT NULL,
    importe_total_linea DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_ocd_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_ocd_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_oc_detalles PRIMARY KEY (ID),
    CONSTRAINT UQ_compras_ocd_oc_sku UNIQUE (ID_orden_compra, ID_variante_sku),
    CONSTRAINT FK_compras_ocd_oc FOREIGN KEY (ID_orden_compra) REFERENCES compras.ordenes_compra(ID),
    CONSTRAINT FK_compras_ocd_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 110. TABLA: compras.recepciones_mercancia (Transaccional Muelle CEDIS)
DROP TABLE IF EXISTS compras.recepciones_mercancia CASCADE;
CREATE TABLE compras.recepciones_mercancia (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_recepcion VARCHAR(35) NOT NULL,
    ID_orden_compra BIGINT NOT NULL,
    numero_remision_proveedor VARCHAR(60) NOT NULL,
    fecha_ingreso_muelle TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_rm_fim DEFAULT CURRENT_TIMESTAMP,
    observaciones_chofer_transporte VARCHAR(250) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_rm_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_rm_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_recepciones PRIMARY KEY (ID),
    CONSTRAINT UQ_compras_rm_folio UNIQUE (folio_recepcion),
    CONSTRAINT FK_compras_rm_oc FOREIGN KEY (ID_orden_compra) REFERENCES compras.ordenes_compra(ID));

-- 111. TABLA: compras.recepciones_detalles (Transaccional)
DROP TABLE IF EXISTS compras.recepciones_detalles CASCADE;
CREATE TABLE compras.recepciones_detalles (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_recepcion BIGINT NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    cantidad_recibida_bultos INT NOT NULL,
    cantidad_unidades_inspeccionadas INT NOT NULL,
    temperatura_llegada_celsius DECIMAL(4,1) NULL, -- Crítico para dermocosmética y sueros
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_recd_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_recd_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_recepciones_det PRIMARY KEY (ID),
    CONSTRAINT FK_compras_recd_recepcion FOREIGN KEY (ID_recepcion) REFERENCES compras.recepciones_mercancia(ID),
    CONSTRAINT FK_compras_recd_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 112. TABLA: compras.inspecciones_sanitarias_qa (Transaccional Control de Calidad)
DROP TABLE IF EXISTS compras.inspecciones_sanitarias_qa CASCADE;
CREATE TABLE compras.inspecciones_sanitarias_qa (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_recepcion_detalle BIGINT NOT NULL,
    sellos_sanitarios_intactos BOOLEAN NOT NULL,
    empaque_sin_derrames BOOLEAN NOT NULL,
    codigo_lote_laboratorio VARCHAR(50) NOT NULL,
    fecha_caducidad_impresa DATE NOT NULL,
    dictamen_qa VARCHAR(20) NOT NULL CONSTRAINT CK_compras_qa_dict CHECK (dictamen_qa IN ('APROBADO', 'RECHAZADO_DEVOLVER', 'RETENIDO_EN_CUARENTENA')),
    justificacion_sanitaria VARCHAR(300) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_compras_qa_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_compras_qa_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_compras_inspecciones_qa PRIMARY KEY (ID),
    CONSTRAINT FK_compras_qa_recdetalle FOREIGN KEY (ID_recepcion_detalle) REFERENCES compras.recepciones_detalles(ID));

-- =================================================================================================
-- SECCIÓN 3.2: WMS, LOTES SANITARIOS, CADUCIDAD FEFO Y SENSORES (TABLAS 113 - 126)
-- =================================================================================================

-- 113. TABLA: wms.almacenes_cedis (Maestra Centros de Distribución)
DROP TABLE IF EXISTS wms.almacenes_cedis CASCADE;
CREATE TABLE wms.almacenes_cedis (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_almacen VARCHAR(20) NOT NULL,
    nombre_almacen VARCHAR(100) NOT NULL, -- CEDIS Norte Monclova, CEDIS Centro CDMX
    calle_numero VARCHAR(150) NOT NULL,
    codigo_postal VARCHAR(10) NOT NULL,
    ciudad VARCHAR(80) NOT NULL,
    capacidad_volumetrica_m3 DECIMAL(10,2) NOT NULL,
    cuenta_con_cadena_frio BOOLEAN NOT NULL CONSTRAINT DF_wms_cedis_frio DEFAULT TRUE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_cedis_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_cedis_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_almacenes PRIMARY KEY (ID),
    CONSTRAINT UQ_wms_cedis_codigo UNIQUE (codigo_almacen)
);

-- 114. TABLA: wms.zonas_almacen (Maestra Zonas Operativas)
DROP TABLE IF EXISTS wms.zonas_almacen CASCADE;
CREATE TABLE wms.zonas_almacen (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_almacen BIGINT NOT NULL,
    codigo_zona VARCHAR(20) NOT NULL, -- ZONA_REFRIGERADA, ZONA_COSMETICA_SECA, ZONA_ESMALTES_INFLAMABLE, ZONA_CUARENTENA
    descripcion VARCHAR(150) NOT NULL,
    temperatura_min_celsius DECIMAL(4,1) NOT NULL,
    temperatura_max_celsius DECIMAL(4,1) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_za_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_za_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_zonas PRIMARY KEY (ID),
    CONSTRAINT UQ_wms_za_almacen_zona UNIQUE (ID_almacen, codigo_zona),
    CONSTRAINT FK_wms_za_almacen FOREIGN KEY (ID_almacen) REFERENCES wms.almacenes_cedis(ID));

-- 115. TABLA: wms.pasillos_ubicaciones (Maestra Racks y Bines)
DROP TABLE IF EXISTS wms.pasillos_ubicaciones CASCADE;
CREATE TABLE wms.pasillos_ubicaciones (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_zona_almacen BIGINT NOT NULL,
    codigo_ubicacion VARCHAR(30) NOT NULL, -- P01-R04-N02-B01 (Pasillo-Rack-Nivel-Bin)
    peso_maximo_kg DECIMAL(8,2) NOT NULL,
    es_bloqueada_auditoria BOOLEAN NOT NULL CONSTRAINT DF_wms_pu_bloq DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_pu_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_pu_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_ubicaciones PRIMARY KEY (ID),
    CONSTRAINT UQ_wms_pu_codigo UNIQUE (codigo_ubicacion),
    CONSTRAINT FK_wms_pu_zona FOREIGN KEY (ID_zona_almacen) REFERENCES wms.zonas_almacen(ID));

-- 116. TABLA: wms.tipos_movimiento_inventario (Catálogo 18)
DROP TABLE IF EXISTS wms.tipos_movimiento_inventario CASCADE;
CREATE TABLE wms.tipos_movimiento_inventario (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_movimiento VARCHAR(20) NOT NULL,
    nombre_movimiento VARCHAR(60) NOT NULL, -- ENTRADA_RECEPCION_OC, SALIDA_VENTA_ORDEN, AJUSTE_CONTEO_FISICO, MERMA_CADUCIDAD, TRASPASO_CEDIS
    signo_afectacion INT NOT NULL CONSTRAINT CK_wms_tmi_signo CHECK (signo_afectacion IN (1, -1)),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_tmi_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_tmi_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_tipos_movimiento PRIMARY KEY (ID),
    CONSTRAINT UQ_wms_tmi_codigo UNIQUE (codigo_movimiento)
);

-- 117. TABLA: wms.lotes_fabricacion_sanitaria (Maestra Lotes de Laboratorio - Control FEFO)
DROP TABLE IF EXISTS wms.lotes_fabricacion_sanitaria CASCADE;
CREATE TABLE wms.lotes_fabricacion_sanitaria (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_variante_sku BIGINT NOT NULL,
    numero_lote_fabricante VARCHAR(60) NOT NULL,
    fecha_fabricacion DATE NOT NULL,
    fecha_caducidad DATE NOT NULL, -- Clave para algoritmo FEFO (First Expired, First Out)
    certificado_calidad_lote_url VARCHAR(300) NOT NULL,
    cuarentena_sanitaria BOOLEAN NOT NULL CONSTRAINT DF_wms_lfs_cuarentena DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_lfs_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_lfs_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_lotes PRIMARY KEY (ID),
    CONSTRAINT UQ_wms_lfs_sku_lote UNIQUE (ID_variante_sku, numero_lote_fabricante),
    CONSTRAINT FK_wms_lfs_sku FOREIGN KEY (ID_variante_sku) REFERENCES catalogo.variantes_sku(ID));

-- 118. TABLA: wms.inventario_lotes_ubicacion (Transaccional Stock Físico)
DROP TABLE IF EXISTS wms.inventario_lotes_ubicacion CASCADE;
CREATE TABLE wms.inventario_lotes_ubicacion (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_lote BIGINT NOT NULL,
    ID_ubicacion BIGINT NOT NULL,
    stock_disponible INT NOT NULL CONSTRAINT CK_wms_ilu_disp CHECK (stock_disponible >= 0),
    stock_apartado_pedidos INT NOT NULL CONSTRAINT DF_wms_ilu_apart DEFAULT 0,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_ilu_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_ilu_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_inventario_stock PRIMARY KEY (ID),
    CONSTRAINT UQ_wms_ilu_lote_ubic UNIQUE (ID_lote, ID_ubicacion),
    CONSTRAINT FK_wms_ilu_lote FOREIGN KEY (ID_lote) REFERENCES wms.lotes_fabricacion_sanitaria(ID),
    CONSTRAINT FK_wms_ilu_ubicacion FOREIGN KEY (ID_ubicacion) REFERENCES wms.pasillos_ubicaciones(ID));

-- 119. TABLA: wms.kardex_movimientos (Bitácora Transaccional de Movimientos)
DROP TABLE IF EXISTS wms.kardex_movimientos CASCADE;
CREATE TABLE wms.kardex_movimientos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_inventario_stock BIGINT NOT NULL,
    ID_tipo_movimiento BIGINT NOT NULL,
    cantidad_movimiento INT NOT NULL CONSTRAINT CK_wms_km_cant CHECK (cantidad_movimiento > 0),
    saldo_anterior INT NOT NULL,
    saldo_resultante INT NOT NULL,
    folio_documento_origen VARCHAR(50) NOT NULL, -- Folio de OC, Orden Venta, o Acta Merma
    costo_unitario_movimiento DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_km_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_km_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_kardex PRIMARY KEY (ID),
    CONSTRAINT FK_wms_km_stock FOREIGN KEY (ID_inventario_stock) REFERENCES wms.inventario_lotes_ubicacion(ID),
    CONSTRAINT FK_wms_km_tipo FOREIGN KEY (ID_tipo_movimiento) REFERENCES wms.tipos_movimiento_inventario(ID));

-- 120. TABLA: wms.alertas_caducidad_proxima (Transaccional Alertas FEFO Sanitarias)
DROP TABLE IF EXISTS wms.alertas_caducidad_proxima CASCADE;
CREATE TABLE wms.alertas_caducidad_proxima (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_lote BIGINT NOT NULL,
    dias_restantes_vida_util INT NOT NULL,
    nivel_urgencia VARCHAR(20) NOT NULL CONSTRAINT CK_wms_acp_urg CHECK (nivel_urgencia IN ('PREVENTIVA_90D', 'MODERADA_60D', 'CRITICA_30D', 'EXPIRADO')),
    accion_comercial_sugerida VARCHAR(150) NOT NULL, -- Poner en venta flash con descuento o retirar
    atendida BOOLEAN NOT NULL CONSTRAINT DF_wms_acp_atendida DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_acp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_acp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_alertas_caducidad PRIMARY KEY (ID),
    CONSTRAINT FK_wms_acp_lote FOREIGN KEY (ID_lote) REFERENCES wms.lotes_fabricacion_sanitaria(ID));

-- 121. TABLA: wms.mermas_destruccion_sanitaria (Transaccional Actas Sanitarias COFEPRIS)
DROP TABLE IF EXISTS wms.mermas_destruccion_sanitaria CASCADE;
CREATE TABLE wms.mermas_destruccion_sanitaria (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_acta_destruccion VARCHAR(35) NOT NULL,
    ID_lote BIGINT NOT NULL,
    cantidad_unidades_destruidas INT NOT NULL CONSTRAINT CK_wms_mds_cant CHECK (cantidad_unidades_destruidas >= 1),
    motivo_sanitario VARCHAR(200) NOT NULL, -- Caducado, Contaminación microbiana, Envase quebrado
    empresa_manifiesto_ecologico VARCHAR(120) NOT NULL, -- Empresa de residuos biológico-químicos
    acta_circunstanciada_url VARCHAR(300) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_mds_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_mds_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_mermas_destruccion PRIMARY KEY (ID),
    CONSTRAINT UQ_wms_mds_folio UNIQUE (folio_acta_destruccion),
    CONSTRAINT FK_wms_mds_lote FOREIGN KEY (ID_lote) REFERENCES wms.lotes_fabricacion_sanitaria(ID));

-- 122. TABLA: wms.transferencias_almacenes (Transaccional)
DROP TABLE IF EXISTS wms.transferencias_almacenes CASCADE;
CREATE TABLE wms.transferencias_almacenes (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_transferencia VARCHAR(35) NOT NULL,
    ID_almacen_origen BIGINT NOT NULL,
    ID_almacen_destino BIGINT NOT NULL,
    estado_transferencia VARCHAR(20) NOT NULL CONSTRAINT CK_wms_ta_est CHECK (estado_transferencia IN ('SOLICITADA', 'EN_TRANSITO', 'RECIBIDA_COMPLETA', 'DISCREPANCIA')),
    fecha_despacho TIMESTAMP(3) NULL,
    fecha_arribo TIMESTAMP(3) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_ta_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_ta_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_transferencias PRIMARY KEY (ID),
    CONSTRAINT UQ_wms_ta_folio UNIQUE (folio_transferencia),
    CONSTRAINT FK_wms_ta_origen FOREIGN KEY (ID_almacen_origen) REFERENCES wms.almacenes_cedis(ID),
    CONSTRAINT FK_wms_ta_destino FOREIGN KEY (ID_almacen_destino) REFERENCES wms.almacenes_cedis(ID));

-- 123. TABLA: wms.transferencias_detalles (Transaccional)
DROP TABLE IF EXISTS wms.transferencias_detalles CASCADE;
CREATE TABLE wms.transferencias_detalles (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_transferencia BIGINT NOT NULL,
    ID_lote BIGINT NOT NULL,
    cantidad_enviada INT NOT NULL CONSTRAINT CK_wms_td_cant CHECK (cantidad_enviada >= 1),
    cantidad_recibida INT NOT NULL CONSTRAINT DF_wms_td_recib DEFAULT 0,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_td_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_td_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_transferencias_det PRIMARY KEY (ID),
    CONSTRAINT FK_wms_td_transf FOREIGN KEY (ID_transferencia) REFERENCES wms.transferencias_almacenes(ID),
    CONSTRAINT FK_wms_td_lote FOREIGN KEY (ID_lote) REFERENCES wms.lotes_fabricacion_sanitaria(ID));

-- 124. TABLA: wms.conteos_ciclicos_auditoria (Transaccional Auditoría FBD)
DROP TABLE IF EXISTS wms.conteos_ciclicos_auditoria CASCADE;
CREATE TABLE wms.conteos_ciclicos_auditoria (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_auditoria VARCHAR(35) NOT NULL,
    ID_almacen BIGINT NOT NULL,
    fecha_conteo DATE NOT NULL,
    tipo_conteo VARCHAR(20) NOT NULL CONSTRAINT CK_wms_cca_tipo CHECK (tipo_conteo IN ('ALEATORIO', 'ALTO_VALOR_SKU', 'PROXIMO_A_CADUCAR')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_cca_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_cca_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_conteos_auditoria PRIMARY KEY (ID),
    CONSTRAINT UQ_wms_cca_folio UNIQUE (folio_auditoria),
    CONSTRAINT FK_wms_cca_almacen FOREIGN KEY (ID_almacen) REFERENCES wms.almacenes_cedis(ID));

-- 125. TABLA: wms.conteos_ciclicos_detalles (Transaccional)
DROP TABLE IF EXISTS wms.conteos_ciclicos_detalles CASCADE;
CREATE TABLE wms.conteos_ciclicos_detalles (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_conteo_ciclico BIGINT NOT NULL,
    ID_inventario_stock BIGINT NOT NULL,
    stock_sistema_teorico INT NOT NULL,
    stock_conteo_fisico INT NOT NULL,
    diferencia_piezas INT NOT NULL,
    justificacion_ajuste VARCHAR(250) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_ccd_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_ccd_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_conteos_detalles PRIMARY KEY (ID),
    CONSTRAINT FK_wms_ccd_conteo FOREIGN KEY (ID_conteo_ciclico) REFERENCES wms.conteos_ciclicos_auditoria(ID),
    CONSTRAINT FK_wms_ccd_stock FOREIGN KEY (ID_inventario_stock) REFERENCES wms.inventario_lotes_ubicacion(ID));

-- 126. TABLA: wms.monitoreo_temperatura_humedad (Transaccional IoT Dermocosmética)
DROP TABLE IF EXISTS wms.monitoreo_temperatura_humedad CASCADE;
CREATE TABLE wms.monitoreo_temperatura_humedad (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_zona_almacen BIGINT NOT NULL,
    codigo_sensor_iot VARCHAR(30) NOT NULL,
    temperatura_registrada_celsius DECIMAL(4,1) NOT NULL,
    humedad_relativa_porcentaje DECIMAL(4,1) NOT NULL,
    alerta_fuera_de_rango BOOLEAN NOT NULL CONSTRAINT DF_wms_mth_alerta DEFAULT FALSE,
    fecha_hora_lectura TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_mth_fhl DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_wms_mth_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_wms_mth_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_wms_monitoreo_iot PRIMARY KEY (ID),
    CONSTRAINT FK_wms_mth_zona FOREIGN KEY (ID_zona_almacen) REFERENCES wms.zonas_almacen(ID));

-- =================================================================================================
-- SECCIÓN 3.3: LOGÍSTICA, ENVÍOS, ÚLTIMA MILLA Y PAQUETERÍAS (TABLAS 127 - 138)
-- =================================================================================================

-- 127. TABLA: envios.transportistas_paqueterias (Catálogo 19)
DROP TABLE IF EXISTS envios.transportistas_paqueterias CASCADE;
CREATE TABLE envios.transportistas_paqueterias (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_transportista VARCHAR(20) NOT NULL,
    nombre_comercial VARCHAR(60) NOT NULL, -- DHL_EXPRESS, FEDEX, ESTAFETA, REDPACK, REPARTO_LOCAL_PROPIO
    api_endpoint_tracking VARCHAR(250) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_tp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_tp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_transportistas PRIMARY KEY (ID),
    CONSTRAINT UQ_envios_tp_codigo UNIQUE (codigo_transportista)
);

-- 128. TABLA: envios.tipos_servicio_envio (Catálogo 20)
DROP TABLE IF EXISTS envios.tipos_servicio_envio CASCADE;
CREATE TABLE envios.tipos_servicio_envio (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_servicio VARCHAR(20) NOT NULL,
    nombre_servicio VARCHAR(60) NOT NULL, -- DIA_SIGUIENTE, ESTANDAR_TERRESTRE_3_5_DIAS, MISMO_DIA_EXPRESS
    tiempo_garantizado_horas INT NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_tse_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_tse_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_tipos_servicio PRIMARY KEY (ID),
    CONSTRAINT UQ_envios_tse_codigo UNIQUE (codigo_servicio)
);

-- 129. TABLA: envios.tarifas_zonas_postales (Transaccional Matriz Tarifaria)
DROP TABLE IF EXISTS envios.tarifas_zonas_postales CASCADE;
CREATE TABLE envios.tarifas_zonas_postales (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_transportista BIGINT NOT NULL,
    ID_servicio_envio BIGINT NOT NULL,
    codigo_postal_origen_prefijo VARCHAR(3) NOT NULL,
    codigo_postal_destino_prefijo VARCHAR(3) NOT NULL,
    peso_limite_kg DECIMAL(6,2) NOT NULL,
    costo_base_envio DECIMAL(12,2) NOT NULL,
    costo_kg_adicional DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_tzp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_tzp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_tarifas PRIMARY KEY (ID),
    CONSTRAINT FK_envios_tzp_transp FOREIGN KEY (ID_transportista) REFERENCES envios.transportistas_paqueterias(ID),
    CONSTRAINT FK_envios_tzp_servicio FOREIGN KEY (ID_servicio_envio) REFERENCES envios.tipos_servicio_envio(ID));

-- 130. TABLA: envios.despachos_orden (Maestra Transaccional de Envíos)
DROP TABLE IF EXISTS envios.despachos_orden CASCADE;
CREATE TABLE envios.despachos_orden (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_despacho VARCHAR(35) NOT NULL,
    ID_orden_split BIGINT NOT NULL,
    ID_transportista BIGINT NOT NULL,
    ID_servicio_envio BIGINT NOT NULL,
    fecha_recoleccion_paqueteria TIMESTAMP(3) NULL,
    fecha_promesa_entrega DATE NOT NULL,
    fecha_entrega_real TIMESTAMP(3) NULL,
    estado_envio VARCHAR(25) NOT NULL CONSTRAINT CK_envios_do_est CHECK (estado_envio IN ('PREPARANDO_PAQUETE', 'RECOLECTADO', 'EN_TRANSITO', 'EN_RUTA_LOCAL', 'ENTREGADO', 'INCIDENCIA')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_do_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_do_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_despachos PRIMARY KEY (ID),
    CONSTRAINT UQ_envios_do_folio UNIQUE (folio_despacho),
    CONSTRAINT FK_envios_do_split FOREIGN KEY (ID_orden_split) REFERENCES ventas.ordenes_splits_almacen(ID),
    CONSTRAINT FK_envios_do_transp FOREIGN KEY (ID_transportista) REFERENCES envios.transportistas_paqueterias(ID),
    CONSTRAINT FK_envios_do_servicio FOREIGN KEY (ID_servicio_envio) REFERENCES envios.tipos_servicio_envio(ID));

-- 131. TABLA: envios.paquetes_bultos (Transaccional)
DROP TABLE IF EXISTS envios.paquetes_bultos CASCADE;
CREATE TABLE envios.paquetes_bultos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_despacho BIGINT NOT NULL,
    codigo_bulto VARCHAR(40) NOT NULL,
    peso_bruto_kg DECIMAL(6,2) NOT NULL,
    alto_cm DECIMAL(5,1) NOT NULL,
    ancho_cm DECIMAL(5,1) NOT NULL,
    largo_cm DECIMAL(5,1) NOT NULL,
    peso_volumetrico_kg NUMERIC(10,3) GENERATED ALWAYS AS (alto_cm * ancho_cm * largo_cm / 5000.0) STORED,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_pb_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_pb_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_paquetes PRIMARY KEY (ID),
    CONSTRAINT UQ_envios_pb_codigo UNIQUE (codigo_bulto),
    CONSTRAINT FK_envios_pb_despacho FOREIGN KEY (ID_despacho) REFERENCES envios.despachos_orden(ID));

-- 132. TABLA: envios.paquetes_contenido_lotes (Transaccional Trazabilidad Sanitaria en Envío)
DROP TABLE IF EXISTS envios.paquetes_contenido_lotes CASCADE;
CREATE TABLE envios.paquetes_contenido_lotes (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_paquete_bulto BIGINT NOT NULL,
    ID_orden_detalle BIGINT NOT NULL,
    ID_lote BIGINT NOT NULL,
    cantidad_piezas_en_paquete INT NOT NULL CONSTRAINT CK_envios_pcl_cant CHECK (cantidad_piezas_en_paquete >= 1),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_pcl_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_pcl_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_contenido_lotes PRIMARY KEY (ID),
    CONSTRAINT FK_envios_pcl_paquete FOREIGN KEY (ID_paquete_bulto) REFERENCES envios.paquetes_bultos(ID),
    CONSTRAINT FK_envios_pcl_ordendet FOREIGN KEY (ID_orden_detalle) REFERENCES ventas.ordenes_detalles(ID),
    CONSTRAINT FK_envios_pcl_lote FOREIGN KEY (ID_lote) REFERENCES wms.lotes_fabricacion_sanitaria(ID));

-- 133. TABLA: envios.guias_rastreo (Transaccional Guías de Paquetería)
DROP TABLE IF EXISTS envios.guias_rastreo CASCADE;
CREATE TABLE envios.guias_rastreo (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_paquete_bulto BIGINT NOT NULL,
    numero_guia_tracking VARCHAR(80) NOT NULL,
    url_rastreo_directo VARCHAR(300) NOT NULL,
    etiqueta_pdf_base64_url VARCHAR(300) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_gr_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_gr_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_guias PRIMARY KEY (ID),
    CONSTRAINT UQ_envios_gr_guia UNIQUE (numero_guia_tracking),
    CONSTRAINT FK_envios_gr_paquete FOREIGN KEY (ID_paquete_bulto) REFERENCES envios.paquetes_bultos(ID));

-- 134. TABLA: envios.eventos_tracking_bitacora (Bitácora de Webhooks)
DROP TABLE IF EXISTS envios.eventos_tracking_bitacora CASCADE;
CREATE TABLE envios.eventos_tracking_bitacora (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_guia_rastreo BIGINT NOT NULL,
    codigo_estatus_paqueteria VARCHAR(40) NOT NULL,
    descripcion_evento VARCHAR(250) NOT NULL,
    ubicacion_ciudad_evento VARCHAR(100) NOT NULL,
    fecha_hora_evento TIMESTAMP(3) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_etb_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_etb_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_eventos_tracking PRIMARY KEY (ID),
    CONSTRAINT FK_envios_etb_guia FOREIGN KEY (ID_guia_rastreo) REFERENCES envios.guias_rastreo(ID));

-- 135. TABLA: envios.intentos_entrega_fallidos (Transaccional)
DROP TABLE IF EXISTS envios.intentos_entrega_fallidos CASCADE;
CREATE TABLE envios.intentos_entrega_fallidos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_despacho BIGINT NOT NULL,
    numero_visita INT NOT NULL CONSTRAINT CK_envios_ief_visita CHECK (numero_visita BETWEEN 1 AND 3),
    motivo_no_entrega VARCHAR(150) NOT NULL, -- Domicilio cerrado, Destinatario ausente
    fecha_intento TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_ief_fi DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_ief_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_ief_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_intentos_fallidos PRIMARY KEY (ID),
    CONSTRAINT FK_envios_ief_despacho FOREIGN KEY (ID_despacho) REFERENCES envios.despachos_orden(ID));

-- 136. TABLA: envios.incidencias_logisticas (Transaccional Siniestros)
DROP TABLE IF EXISTS envios.incidencias_logisticas CASCADE;
CREATE TABLE envios.incidencias_logisticas (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_despacho BIGINT NOT NULL,
    tipo_incidencia VARCHAR(30) NOT NULL CONSTRAINT CK_envios_il_tipo CHECK (tipo_incidencia IN ('EXTRAVIO_TOTAL', 'PAQUETE_DANADO_DERRAME', 'ROBO_EN_TRANSITO', 'DIRECCION_INEXISTENTE')),
    descripcion_hechos VARCHAR(500) NOT NULL,
    indemnizacion_reclamada DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_il_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_il_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_incidencias PRIMARY KEY (ID),
    CONSTRAINT FK_envios_il_despacho FOREIGN KEY (ID_despacho) REFERENCES envios.despachos_orden(ID));

-- 137. TABLA: envios.seguros_mercancia (Transaccional Pólizas de Carga)
DROP TABLE IF EXISTS envios.seguros_mercancia CASCADE;
CREATE TABLE envios.seguros_mercancia (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_despacho BIGINT NOT NULL,
    aseguradora VARCHAR(100) NOT NULL,
    numero_poliza VARCHAR(60) NOT NULL,
    valor_asegurado DECIMAL(12,2) NOT NULL,
    costo_prima DECIMAL(12,2) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_sm_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_sm_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_seguros PRIMARY KEY (ID),
    CONSTRAINT UQ_envios_sm_despacho UNIQUE (ID_despacho),
    CONSTRAINT FK_envios_sm_despacho FOREIGN KEY (ID_despacho) REFERENCES envios.despachos_orden(ID));

-- 138. TABLA: envios.puntos_recoleccion_pickup (Maestra Lockers y Puntos de Entrega)
DROP TABLE IF EXISTS envios.puntos_recoleccion_pickup CASCADE;
CREATE TABLE envios.puntos_recoleccion_pickup (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_transportista BIGINT NOT NULL,
    ID_almacen_origen BIGINT NOT NULL,
    codigo_locker VARCHAR(30) NOT NULL,
    nombre_establecimiento VARCHAR(100) NOT NULL,
    direccion_completa VARCHAR(200) NOT NULL,
    horario_atencion VARCHAR(100) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_envios_prp_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_envios_prp_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_envios_pickup PRIMARY KEY (ID),
    CONSTRAINT UQ_envios_prp_codigo UNIQUE (codigo_locker),
    CONSTRAINT FK_envios_prp_transp FOREIGN KEY (ID_transportista) REFERENCES envios.transportistas_paqueterias(ID),
    CONSTRAINT FK_envios_prp_almacen FOREIGN KEY (ID_almacen_origen) REFERENCES wms.almacenes_cedis(ID)
);

-- =================================================================================================
-- SECCIÓN 3.4: POSTVENTA, RMA, FARMACOVIGILANCIA Y AUDITORÍA FORENSE (TABLAS 139 - 150)
-- =================================================================================================

-- 139. TABLA: postventa.motivos_devolucion_rma (Catálogo 21)
DROP TABLE IF EXISTS postventa.motivos_devolucion_rma CASCADE;
CREATE TABLE postventa.motivos_devolucion_rma (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_motivo VARCHAR(20) NOT NULL,
    descripcion_motivo VARCHAR(150) NOT NULL, -- REACCION_ALERGICA_CUTANEA, TONO_INCORRECTO, PRODUCTO_CADUCADO, SELLO_ROTO, NO_SATISFECHO
    requiere_dictamen_medico BOOLEAN NOT NULL CONSTRAINT DF_postventa_mr_medico DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_postventa_mr_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_postventa_mr_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_postventa_motivos_rma PRIMARY KEY (ID),
    CONSTRAINT UQ_postventa_mr_codigo UNIQUE (codigo_motivo)
);

-- 140. TABLA: postventa.solicitudes_rma (Maestra Devoluciones Sanitarias)
DROP TABLE IF EXISTS postventa.solicitudes_rma CASCADE;
CREATE TABLE postventa.solicitudes_rma (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_rma VARCHAR(35) NOT NULL,
    ID_orden BIGINT NOT NULL,
    ID_motivo_rma BIGINT NOT NULL,
    estado_rma VARCHAR(20) NOT NULL CONSTRAINT CK_postventa_srma_est CHECK (estado_rma IN ('SOLICITADA', 'GUIA_RETORNO_EMITIDA', 'RECIBIDA_EN_QA', 'APROBADA_REEMBOLSAR', 'RECHAZADA_POR_HIGIENE')),
    fotografia_evidencia_url VARCHAR(300) NOT NULL,
    descripcion_caso_cliente VARCHAR(500) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_postventa_srma_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_postventa_srma_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_postventa_solicitudes_rma PRIMARY KEY (ID),
    CONSTRAINT UQ_postventa_srma_folio UNIQUE (folio_rma),
    CONSTRAINT FK_postventa_srma_orden FOREIGN KEY (ID_orden) REFERENCES ventas.ordenes(ID),
    CONSTRAINT FK_postventa_srma_motivo FOREIGN KEY (ID_motivo_rma) REFERENCES postventa.motivos_devolucion_rma(ID));

-- 141. TABLA: postventa.rma_detalles (Transaccional)
DROP TABLE IF EXISTS postventa.rma_detalles CASCADE;
CREATE TABLE postventa.rma_detalles (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_solicitud_rma BIGINT NOT NULL,
    ID_orden_detalle BIGINT NOT NULL,
    cantidad_devuelta INT NOT NULL CONSTRAINT CK_postventa_rd_cant CHECK (cantidad_devuelta >= 1),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_postventa_rd_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_postventa_rd_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_postventa_rma_detalles PRIMARY KEY (ID),
    CONSTRAINT FK_postventa_rd_rma FOREIGN KEY (ID_solicitud_rma) REFERENCES postventa.solicitudes_rma(ID),
    CONSTRAINT FK_postventa_rd_ordendet FOREIGN KEY (ID_orden_detalle) REFERENCES ventas.ordenes_detalles(ID));

-- 142. TABLA: postventa.inspeccion_sanitaria_retorno (Transaccional Higiene y Destino)
DROP TABLE IF EXISTS postventa.inspeccion_sanitaria_retorno CASCADE;
CREATE TABLE postventa.inspeccion_sanitaria_retorno (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_rma_detalle BIGINT NOT NULL,
    sello_seguridad_fue_abierto BOOLEAN NOT NULL,
    contenido_usado_porcentaje DECIMAL(4,1) NOT NULL,
    destino_sanitario_autorizado VARCHAR(30) NOT NULL CONSTRAINT CK_postventa_isr_dest CHECK (destino_sanitario_autorizado IN ('DESTRUCCION_INMEDIATA_RESIDUOS', 'DONACION_REACONDICIONADA', 'REINGRESO_STOCK_SELLADO')),
    dictamen_auditor VARCHAR(250) NOT NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_postventa_isr_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_postventa_isr_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_postventa_inspeccion_retorno PRIMARY KEY (ID),
    CONSTRAINT UQ_postventa_isr_rmadetalle UNIQUE (ID_rma_detalle),
    CONSTRAINT FK_postventa_isr_rmadetalle FOREIGN KEY (ID_rma_detalle) REFERENCES postventa.rma_detalles(ID));

-- 143. TABLA: postventa.tickets_soporte (Maestra Atención al Cliente)
DROP TABLE IF EXISTS postventa.tickets_soporte CASCADE;
CREATE TABLE postventa.tickets_soporte (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_ticket VARCHAR(35) NOT NULL,
    ID_cliente BIGINT NOT NULL,
    asunto VARCHAR(120) NOT NULL,
    categoria_ticket VARCHAR(30) NOT NULL CONSTRAINT CK_postventa_ts_cat CHECK (categoria_ticket IN ('ENVIO_DEMORADO', 'ASESORIA_DERMATOLOGICA', 'FACTURACION_CFDI', 'PRODUCTO_DEFECTUOSO')),
    prioridad VARCHAR(20) NOT NULL CONSTRAINT CK_postventa_ts_prio CHECK (prioridad IN ('BAJA', 'MEDIA', 'ALTA', 'URGENTE')),
    estado_ticket VARCHAR(20) NOT NULL CONSTRAINT CK_postventa_ts_est CHECK (estado_ticket IN ('ABIERTO', 'EN_PROCESO', 'ESPERANDO_CLIENTE', 'RESUELTO', 'CERRADO')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_postventa_ts_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_postventa_ts_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_postventa_tickets PRIMARY KEY (ID),
    CONSTRAINT UQ_postventa_ts_folio UNIQUE (folio_ticket),
    CONSTRAINT FK_postventa_ts_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID));

-- 144. TABLA: postventa.tickets_mensajes (Transaccional)
DROP TABLE IF EXISTS postventa.tickets_mensajes CASCADE;
CREATE TABLE postventa.tickets_mensajes (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_ticket BIGINT NOT NULL,
    ID_usuario_emisor BIGINT NOT NULL,
    mensaje_cuerpo TEXT NOT NULL,
    adjunto_url VARCHAR(300) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_postventa_tm_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_postventa_tm_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_postventa_tickets_mensajes PRIMARY KEY (ID),
    CONSTRAINT FK_postventa_tm_ticket FOREIGN KEY (ID_ticket) REFERENCES postventa.tickets_soporte(ID),
    CONSTRAINT FK_postventa_tm_usuario FOREIGN KEY (ID_usuario_emisor) REFERENCES seguridad.usuarios(ID));

-- 145. TABLA: postventa.reportes_farmacovigilancia (Transaccional Regulatoria COFEPRIS)
DROP TABLE IF EXISTS postventa.reportes_farmacovigilancia CASCADE;
CREATE TABLE postventa.reportes_farmacovigilancia (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    folio_cofepris_ram VARCHAR(45) NOT NULL, -- Reporte de Reacciones Adversas a Medicamentos / Cosméticos
    ID_cliente BIGINT NOT NULL,
    ID_producto BIGINT NOT NULL,
    ID_lote BIGINT NOT NULL,
    sintomas_reaccion_adversa TEXT NOT NULL,
    requirio_atencion_hospitalaria BOOLEAN NOT NULL,
    fecha_aparicion_sintomas DATE NOT NULL,
    notificado_a_autoridad_sanitaria BOOLEAN NOT NULL CONSTRAINT DF_postventa_rf_notif DEFAULT FALSE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_postventa_rf_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_postventa_rf_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_postventa_farmacovigilancia PRIMARY KEY (ID),
    CONSTRAINT UQ_postventa_rf_folio UNIQUE (folio_cofepris_ram),
    CONSTRAINT FK_postventa_rf_cliente FOREIGN KEY (ID_cliente) REFERENCES clientes.clientes(ID),
    CONSTRAINT FK_postventa_rf_producto FOREIGN KEY (ID_producto) REFERENCES catalogo.productos_maestros(ID),
    CONSTRAINT FK_postventa_rf_lote FOREIGN KEY (ID_lote) REFERENCES wms.lotes_fabricacion_sanitaria(ID));

-- 146. TABLA: auditoria.tipos_evento_sistema (Catálogo 22)
DROP TABLE IF EXISTS auditoria.tipos_evento_sistema CASCADE;
CREATE TABLE auditoria.tipos_evento_sistema (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    codigo_evento VARCHAR(30) NOT NULL,
    nombre_evento VARCHAR(80) NOT NULL, -- LOGIN_EXITOSO, INTENTO_ACCESO_DENEGADO, MODIFICACION_PRECIOS, BAJA_LOGICA_REGISTRO, EXPORTACION_DATOS_CLIENTES
    nivel_severidad VARCHAR(20) NOT NULL CONSTRAINT CK_auditoria_tes_sev CHECK (nivel_severidad IN ('INFO', 'ADVERTENCIA', 'CRITICO_SEGURIDAD')),
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_auditoria_tes_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_auditoria_tes_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_auditoria_tipos_evento PRIMARY KEY (ID),
    CONSTRAINT UQ_auditoria_tes_codigo UNIQUE (codigo_evento)
);

-- 147. TABLA: auditoria.bitacora_seguridad_global (Bitácora Forense Penal Art. 211 bis)
DROP TABLE IF EXISTS auditoria.bitacora_seguridad_global CASCADE;
CREATE TABLE auditoria.bitacora_seguridad_global (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_tipo_evento BIGINT NOT NULL,
    ID_usuario BIGINT NULL,
    direccion_ip VARCHAR(45) NOT NULL,
    user_agent VARCHAR(350) NOT NULL,
    modulo_origen VARCHAR(60) NOT NULL,
    descripcion_evento VARCHAR(500) NOT NULL,
    firma_integridad_hash VARCHAR(128) NOT NULL, -- Hash SHA-256 de los datos de la fila para evitar manipulación de logs periciales
    fecha_evento TIMESTAMP(3) NOT NULL CONSTRAINT DF_auditoria_bsg_fev DEFAULT CURRENT_TIMESTAMP,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_auditoria_bsg_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_auditoria_bsg_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_auditoria_seguridad PRIMARY KEY (ID),
    CONSTRAINT FK_auditoria_bsg_tipo FOREIGN KEY (ID_tipo_evento) REFERENCES auditoria.tipos_evento_sistema(ID),
    CONSTRAINT FK_auditoria_bsg_usuario FOREIGN KEY (ID_usuario) REFERENCES seguridad.usuarios(ID));

-- 148. TABLA: auditoria.bitacora_cambios_datos (Bitácora DML Trazabilidad Total)
DROP TABLE IF EXISTS auditoria.bitacora_cambios_datos CASCADE;
CREATE TABLE auditoria.bitacora_cambios_datos (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    nombre_tabla VARCHAR(100) NOT NULL,
    id_registro_afectado BIGINT NOT NULL,
    tipo_operacion VARCHAR(15) NOT NULL CONSTRAINT CK_auditoria_bcd_tipo CHECK (tipo_operacion IN ('INSERT', 'UPDATE', 'SOFT_DELETE')),
    valores_anteriores_json TEXT NULL,
    valores_nuevos_json TEXT NOT NULL,
    motivo_cambio VARCHAR(250) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_auditoria_bcd_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_auditoria_bcd_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_auditoria_cambios PRIMARY KEY (ID),
    CONSTRAINT FK_auditoria_bcd_usuario FOREIGN KEY (creado_por) REFERENCES seguridad.usuarios(ID)
);

-- 149. TABLA: sistema.parametros_configuracion (Maestra Parámetros del Sistema)
DROP TABLE IF EXISTS sistema.parametros_configuracion CASCADE;
CREATE TABLE sistema.parametros_configuracion (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    clave_parametro VARCHAR(60) NOT NULL,
    valor_parametro VARCHAR(500) NOT NULL,
    tipo_dato VARCHAR(20) NOT NULL CONSTRAINT CK_sistema_pc_tipo CHECK (tipo_dato IN ('STRING', 'INTEGER', 'DECIMAL', 'BOOLEAN', 'JSON')),
    descripcion VARCHAR(250) NOT NULL,
    es_modificable_en_caliente BOOLEAN NOT NULL CONSTRAINT DF_sistema_pc_mc DEFAULT TRUE,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_sistema_pc_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_sistema_pc_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_sistema_parametros PRIMARY KEY (ID),
    CONSTRAINT UQ_sistema_pc_clave UNIQUE (clave_parametro),
    CONSTRAINT FK_sistema_pc_usuario FOREIGN KEY (creado_por) REFERENCES seguridad.usuarios(ID)
);

-- 150. TABLA: sistema.notificaciones_push_email (Transaccional Cola de Mensajes)
DROP TABLE IF EXISTS sistema.notificaciones_push_email CASCADE;
CREATE TABLE sistema.notificaciones_push_email (
    ID BIGINT GENERATED ALWAYS AS IDENTITY NOT NULL,
    ID_usuario_destinatario BIGINT NOT NULL,
    tipo_canal VARCHAR(20) NOT NULL CONSTRAINT CK_sistema_npe_canal CHECK (tipo_canal IN ('EMAIL', 'PUSH_APP', 'SMS', 'WHATSAPP')),
    titulo_asunto VARCHAR(150) NOT NULL,
    cuerpo_mensaje TEXT NOT NULL,
    enviada BOOLEAN NOT NULL CONSTRAINT DF_sistema_npe_env DEFAULT FALSE,
    fecha_envio TIMESTAMP(3) NULL,
    error_envio VARCHAR(300) NULL,
    -- Columnas estándar de Auditoría y Soft Delete
    activo BOOLEAN NOT NULL CONSTRAINT DF_sistema_npe_activo DEFAULT TRUE,
    fecha_creacion TIMESTAMP(3) NOT NULL CONSTRAINT DF_sistema_npe_fc DEFAULT CURRENT_TIMESTAMP,
    creado_por BIGINT NOT NULL,
    fecha_modificacion TIMESTAMP(3) NULL,
    modificado_por BIGINT NULL,
    fecha_baja TIMESTAMP(3) NULL,
    eliminado_por BIGINT NULL,
    CONSTRAINT PK_sistema_notificaciones PRIMARY KEY (ID),
    CONSTRAINT FK_sistema_npe_usuario FOREIGN KEY (ID_usuario_destinatario) REFERENCES seguridad.usuarios(ID));

-- =================================================================================================
-- ÍNDICES SECUNDARIOS ESTRATÉGICOS - SUBMÓDULO 1 (RENDIMIENTO EN AUTENTICACIÓN, CLIENTES Y CATÁLOGO)
-- =================================================================================================
CREATE INDEX IX_seguridad_usuarios_activo_email ON seguridad.usuarios (activo, email);
CREATE INDEX IX_seguridad_usuarios_roles_ur ON seguridad.usuarios_roles (ID_usuario, ID_rol);
CREATE INDEX IX_seguridad_sesiones_usuario_rev ON seguridad.sesiones_activas (ID_usuario, revocada, fecha_expiracion);
CREATE INDEX IX_seguridad_intentos_login_ip ON seguridad.intentos_login (direccion_ip, fecha_creacion);
CREATE INDEX IX_clientes_clientes_usuario_act ON clientes.clientes (ID_usuario, activo);
CREATE INDEX IX_clientes_condiciones_cli ON clientes.cliente_condiciones (ID_cliente, ID_condicion_dermatologica);
CREATE INDEX IX_catalogo_productos_marca_sub ON catalogo.productos_maestros (ID_marca, ID_subcategoria, ID_laboratorio);
CREATE INDEX IX_catalogo_variantes_prod_act ON catalogo.variantes_sku (ID_producto, activo);
CREATE INDEX IX_catalogo_formula_prod_ing ON catalogo.formula_ingredientes (ID_producto, ID_ingrediente);
CREATE INDEX IX_catalogo_alergenos_ing_riesgo ON catalogo.alergenos_ingrediente (ID_ingrediente, clasificacion_riesgo);
-- =================================================================================================
-- ÍNDICES SECUNDARIOS ESTRATÉGICOS - SUBMÓDULO 2 (VENTAS, SUSCRIPCIONES, PAGOS, CFDI Y PROMOCIONES)
-- =================================================================================================
CREATE INDEX IX_ventas_ordenes_cliente_fecha ON ventas.ordenes (ID_cliente, fecha_orden);
CREATE INDEX IX_ventas_ordenes_estado_activo ON ventas.ordenes (ID_estado_orden, activo);
CREATE INDEX IX_ventas_ordenes_det_orden_sku ON ventas.ordenes_detalles (ID_orden, ID_variante_sku);
CREATE INDEX IX_ventas_suscrip_cliente_est ON ventas.suscripciones_cliente (ID_cliente, estado_suscripcion);
CREATE INDEX IX_ventas_suscrip_cal_susc_est ON ventas.suscripciones_calendario_entregas (ID_suscripcion_cliente, estado_despacho);
CREATE INDEX IX_pagos_tx_orden_estado ON pagos.transacciones (ID_orden, estado_pago);
CREATE INDEX IX_pagos_antifraude_orden_riesgo ON pagos.evaluaciones_antifraude (ID_orden, nivel_riesgo, score_riesgo_total);
CREATE INDEX IX_fiscal_facturas_orden_estado ON fiscal.facturas_cfdi (ID_orden, estado_cfdi);
CREATE INDEX IX_promos_cupones_camp_activo ON promos.cupones (ID_campania, activo);
CREATE INDEX IX_promos_redenciones_cup_ord ON promos.redenciones_cupones (ID_cupon, ID_orden);
-- =================================================================================================
-- ÍNDICES SECUNDARIOS ESTRATÉGICOS - SUBMÓDULO 3 (COMPRAS, WMS FEFO, IOT FRÍO, ENVÍOS Y AUDITORÍA)
-- =================================================================================================
CREATE INDEX IX_compras_oc_prov_fecha ON compras.ordenes_compra (ID_proveedor, fecha_emision);
CREATE INDEX IX_compras_recep_oc_fecha ON compras.recepciones_mercancia (ID_orden_compra, fecha_ingreso_muelle);
CREATE INDEX IX_compras_qa_detalle_dictamen ON compras.inspecciones_sanitarias_qa (ID_recepcion_detalle, dictamen_qa);
CREATE INDEX IX_wms_lotes_sku_caducidad ON wms.lotes_fabricacion_sanitaria (ID_variante_sku, fecha_caducidad);
CREATE INDEX IX_wms_inv_lote_ubicacion ON wms.inventario_lotes_ubicacion (ID_lote, ID_ubicacion);
CREATE INDEX IX_wms_alertas_lote_atendida ON wms.alertas_caducidad_proxima (ID_lote, atendida, dias_restantes_vida_util);
CREATE INDEX IX_wms_telemetria_zona_fecha ON wms.monitoreo_temperatura_humedad (ID_zona_almacen, alerta_fuera_de_rango, fecha_hora_lectura);
CREATE INDEX IX_envios_despachos_split_est ON envios.despachos_orden (ID_orden_split, estado_envio);
CREATE INDEX IX_postventa_rma_orden_motivo ON postventa.solicitudes_rma (ID_orden, ID_motivo_rma, estado_rma);
CREATE INDEX IX_auditoria_cambios_tipo_fecha ON auditoria.bitacora_cambios_datos (tipo_operacion, fecha_creacion);
