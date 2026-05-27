# Plan DevSecOps

## Seguridad en desarrollo

- Validar entradas del cliente y del API.
- Evitar credenciales en el repositorio.
- Usar variables de entorno para secretos.
- Aplicar hashing seguro de contrasenas.
- Registrar eventos criticos de auditoria.

## Integracion continua

El pipeline inicial ejecuta:

- Instalacion de dependencias Python.
- Pruebas automaticas con pytest.
- Analisis estatico con Bandit.
- Build del frontend.

## Escaneo de seguridad

Herramientas consideradas:

- Bandit para codigo Python.
- Trivy para dependencias, imagenes o filesystem.
- Nmap para analisis de red desde Kali Linux.
- OWASP Dependency Check como alternativa para dependencias.

## Gestion de vulnerabilidades

Cada hallazgo debe registrar:

- Identificador.
- Descripcion.
- Severidad.
- Evidencia.
- Mitigacion aplicada.
- Estado.
