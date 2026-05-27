# Proyecto de Ingenieria de Seguridad del Software

## Nombre del proyecto

**Desarrollo de una Plataforma Web Segura de Firma Digital y Validacion Criptografica Aplicando DevSecOps**

## Objetivo general

Desarrollar una plataforma web segura capaz de generar, firmar, validar y proteger documentos digitales mediante funciones hash, criptografia simetrica y asimetrica, certificados digitales y una Autoridad Certificadora simulada, aplicando practicas DevSecOps en un entorno virtualizado de red controlada en Linux.

## Alcance funcional

La plataforma debe permitir:

- Autenticacion segura y control de sesiones.
- Gestion CRUD de usuarios, certificados y documentos.
- Generacion y comparacion de hashes SHA-256.
- Cifrado y descifrado de archivos con AES.
- Firma digital y verificacion de documentos con RSA.
- Emision, validacion, expiracion y revocacion de certificados digitales.
- Simulacion basica de una Autoridad Certificadora.
- Registro de accesos, eventos criptograficos, errores y validaciones.
- Pruebas automaticas, analisis estatico y escaneo de seguridad.
- Recoleccion de metricas para analisis estadistico experimental.

## Tecnologias propuestas

| Capa | Tecnologia | Proposito |
| --- | --- | --- |
| Frontend | React, HTML, CSS, JavaScript | Interfaz web para usuarios, documentos, certificados y resultados criptograficos. |
| Backend | Python, FastAPI | API REST, reglas de negocio, autenticacion y servicios criptograficos. |
| Base de datos | SQLite en desarrollo, PostgreSQL en despliegue | Persistencia de usuarios, documentos, certificados, auditoria y resultados de pruebas. |
| Criptografia | cryptography, hashlib | SHA-256, AES, RSA, firmas digitales y certificados. |
| Pruebas | pytest | Pruebas unitarias y de integracion del backend. |
| DevSecOps | GitHub Actions, Bandit, Trivy, Nmap | Integracion continua, analisis estatico y escaneo de seguridad. |
| Analisis estadistico | Python, pandas, matplotlib, Jupyter Notebook | Calculo de metricas y graficos de resultados experimentales. |
| Entorno virtualizado | Ubuntu Server, Ubuntu Desktop, Kali Linux, Metasploitable 2 | Despliegue, cliente legitimo, pruebas de seguridad y laboratorio controlado. |

## Estructura del repositorio

```text
Proyecto-Ingenieria-Seguridad/
├── .github/workflows/          # Automatizacion CI/CD y escaneos basicos
├── backend/                    # API, modelos, servicios criptograficos y pruebas
│   ├── app/
│   │   ├── api/                # Endpoints REST
│   │   ├── core/               # Configuracion, seguridad y dependencias comunes
│   │   ├── models/             # Modelos de dominio y persistencia
│   │   ├── schemas/            # Esquemas de validacion de datos
│   │   └── services/           # Hash, AES, RSA, certificados y auditoria
│   └── tests/                  # Pruebas automatizadas del backend
├── devops/                     # Scripts de seguridad y automatizacion
├── docs/                       # Documentacion tecnica, arquitectura y metodologia
├── frontend/                   # Aplicacion web React
│   └── src/
│       ├── components/         # Componentes reutilizables
│       ├── pages/              # Vistas principales
│       └── services/           # Cliente HTTP hacia la API
├── infrastructure/             # Notas de despliegue y laboratorio virtualizado
└── reports/                    # Evidencias, metricas y resultados experimentales
```

## Modulos principales

### Usuarios

- Registro de usuarios.
- Inicio de sesion seguro.
- Consulta, actualizacion y eliminacion de usuarios.
- Almacenamiento de contrasenas con hash seguro.

### Documentos

- Subida de archivos.
- Calculo de hash SHA-256.
- Firma digital.
- Verificacion de firma.
- Cifrado y descifrado.
- Consulta y eliminacion de documentos.

### Certificados

- Emision de certificados.
- Consulta de certificados.
- Validacion de vigencia y confianza.
- Revocacion.
- Simulacion de Autoridad Certificadora.

### Auditoria

- Registro de accesos.
- Registro de operaciones criptograficas.
- Registro de errores.
- Registro de validaciones y resultados.

## DevSecOps

El proyecto integra seguridad durante el ciclo de vida del software:

- Control de versiones con Git y GitHub.
- Pipeline de integracion continua con GitHub Actions.
- Pruebas automaticas con pytest.
- Analisis estatico de seguridad con Bandit.
- Escaneo de dependencias e imagenes con Trivy.
- Validacion manual de red con Nmap desde Kali Linux.
- Documentacion de vulnerabilidades, severidad y mitigaciones.

## Entorno virtualizado esperado

| Maquina | Rol |
| --- | --- |
| Ubuntu Server | Hospeda backend, base de datos y API criptografica. |
| Ubuntu Desktop | Cliente legitimo para consumir la plataforma. |
| Kali Linux | Escaneo, pruebas de seguridad y validacion de vulnerabilidades. |
| Metasploitable 2 | Objetivo vulnerable para analisis controlado y comparacion de riesgos. |

## Ejecucion inicial

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

En Windows PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

## Pruebas y seguridad

```bash
cd backend
pytest
bandit -r app
```

Escaneo de red desde Kali Linux:

```bash
nmap -sV -O <ip-ubuntu-server>
```

## Metricas experimentales sugeridas

- Tiempo promedio de cifrado.
- Tiempo promedio de validacion de firma.
- Porcentaje de deteccion de alteraciones.
- Tasa de exito de autenticacion.
- Vulnerabilidades detectadas por severidad.
- Porcentaje de vulnerabilidades mitigadas.

Los resultados deben almacenarse en `reports/metrics/` y usarse para tablas, graficos y analisis estadistico.

## Documentacion del proyecto

- [Arquitectura](docs/arquitectura.md)
- [Backlog agil](docs/backlog-agil.md)
- [Plan DevSecOps](docs/devsecops.md)
- [Entorno virtualizado](infrastructure/laboratorio-virtual.md)
- [Registro de vulnerabilidades](reports/vulnerabilidades.md)

## Entregables academicos

- Codigo fuente en repositorio Git funcional.
- Plataforma implementada en entorno virtualizado.
- Informe tecnico.
- Articulo tecnico.
- Video demostrativo.
- Presentacion y defensa final.

## Nota sobre archivos versionados

No se versionan dependencias instaladas, entornos virtuales, archivos temporales, salidas generadas, documentos locales pesados ni credenciales. El repositorio contiene solo codigo, configuracion, documentacion y evidencias utiles para construir, auditar y defender el proyecto.
