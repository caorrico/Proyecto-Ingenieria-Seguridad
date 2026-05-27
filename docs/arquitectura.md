# Arquitectura

## Vision general

La solucion usa una arquitectura cliente-servidor:

- Frontend React para la interaccion con usuarios.
- Backend FastAPI para exponer API REST y ejecutar la logica criptografica.
- Base de datos para persistir usuarios, documentos, certificados, auditoria y resultados.
- Servicios criptograficos separados para hash, AES, RSA, firma digital y certificados.

## Flujo principal

1. El usuario inicia sesion desde el frontend.
2. El frontend consume endpoints seguros del backend.
3. El backend valida entradas, permisos y estado de sesion.
4. Los servicios criptograficos procesan documentos, firmas, hashes o certificados.
5. La base de datos registra resultados y eventos de auditoria.
6. Las evidencias experimentales se exportan para analisis estadistico.

## Componentes esperados

- `api`: rutas HTTP.
- `core`: configuracion, seguridad y dependencias comunes.
- `models`: entidades de persistencia.
- `schemas`: validacion de entradas y salidas.
- `services`: logica criptografica y auditoria.
- `tests`: verificacion automatizada.
