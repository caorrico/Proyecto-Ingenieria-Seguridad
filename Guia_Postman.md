# 🔐 API de Firma Digital y Criptografía

## 📍 URL Base
```
http://localhost:8000
```

## 📚 Documentación Interactiva
[Swagger UI](http://localhost:8000/docs) - http://localhost:8000/docs

---

## ✅ Health Checks

### GET /health
Verifica que el servidor API esté disponible

**Respuesta (200 OK):**
```json
{
    "status": "ok"
}
```

---

### GET /health/db
Verifica que la conexión a la base de datos sea correcta

**Respuesta (200 OK):**
```json
{
    "database": "ok"
}
```

---

## #️⃣ Hash Operations (SHA-256)

### POST /crypto/hash
Calcula el hash SHA-256 de un dato

**Request Body:**
```json
{
    "data": "SGVsbG8gV29ybGQ="
}
```

> 💡 **Nota:** El campo `data` debe estar codificado en **Base64**.
> 
> Ejemplo: `"Hello World"` → `"SGVsbG8gV29ybGQ="`

**Respuesta (200 OK):**
```json
{
    "hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
}
```

---

### POST /crypto/hash/verify
Verifica si un hash coincide con los datos

**Request Body:**
```json
{
    "data": "SGVsbG8gV29ybGQ=",
    "expected_hash": "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
}
```

**Respuesta (200 OK):**
```json
{
    "valid": true
}
```

---

## 🔑 RSA Operations

### POST /crypto/rsa/keys
Genera un par de claves RSA-4096 (privada y pública)

**Request Body:**
```json
{}
```

**Respuesta (200 OK):**
```json
{
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
    "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

> ⚠️ **Importante:** Guarda estas claves. Las usarás para firmar y verificar documentos en próximas solicitudes.

---

## ✍️ Digital Signatures

### POST /crypto/sign
Firma un documento con una clave privada RSA

**Request Body:**
```json
{
    "data": "RG9jdW1lbnRvIGEgZmlybWFy",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\n..."
}
```

**Respuesta (200 OK):**
```json
{
    "signature": "ABC123DEF456GHI789JKL012MNO345PQR..."
}
```

---

### POST /crypto/verify
Verifica la firma de un documento con una clave pública RSA

**Request Body:**
```json
{
    "data": "RG9jdW1lbnRvIGEgZmlybWFy",
    "signature": "ABC123DEF456GHI789JKL012MNO345PQR...",
    "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

**Respuesta (200 OK):**
```json
{
    "valid": true
}
```

---

## 🔒 AES Encryption

### POST /crypto/aes/encrypt
Cifra datos con AES-256-GCM (incluye autenticación)

**Request Body:**
```json
{
    "plaintext": "VGV4dG8gc2VjcmV0bw==",
    "key": null
}
```

> 💡 **Nota:** Si `key` es `null`, el servidor genera una clave automáticamente.
> 
> Si deseas usar una clave específica, debe estar en **Base64** y tener **32 bytes (256 bits)**.

**Respuesta (200 OK):**
```json
{
    "ciphertext": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg==",
    "iv": "1234567890ABCDEF==",
    "tag": "ABCD1234=="
}
```

---

### POST /crypto/aes/decrypt
Descifra datos cifrados con AES-256-GCM

**Request Body:**
```json
{
    "ciphertext": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg==",
    "iv": "1234567890ABCDEF==",
    "tag": "ABCD1234==",
    "key": "la_misma_clave_que_en_encrypt"
}
```

**Respuesta (200 OK):**
```json
{
    "plaintext": "VGV4dG8gc2VjcmV0bw=="
}
```

> ⚠️ **Importante:** Debes usar exactamente la misma **clave, IV y tag** que se generaron durante el cifrado.

---

## 📜 Digital Certificates

### POST /crypto/certificates
Emite un certificado digital usando la Autoridad Certificadora (CA)

**Request Body:**
```json
{
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...",
    "subject_cn": "Juan Pérez",
    "subject_org": "Mi Empresa",
    "subject_country": "MX",
    "validity_days": 365
}
```

**Respuesta (200 OK):**
```json
{
    "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIF...",
    "serial_number": 123456789
}
```

---

### POST /crypto/ca/validate
Valida un certificado contra la Autoridad Certificadora

**Request Body:**
```json
{
    "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIF..."
}
```

**Respuesta (200 OK):**
```json
{
    "valid": true,
    "reason": "Certificate is valid"
}
```

---

### POST /crypto/ca/revoke
Revoca un certificado digital por su número de serie

**URL Query Parameter:**
```
?serial_number=123456789
```

**Request Body:**
```json
{}
```

**Respuesta (200 OK):**
```json
{
    "status": "revoked",
    "serial_number": 123456789
}
```

---

## 🔄 Flujo Completo de Pruebas (Recomendado)

```
1. Health Check
   GET /health
   ↓
2. Database Health Check
   GET /health/db
   ↓
3. Generate Hash
   POST /crypto/hash
   ↓
4. Verify Hash
   POST /crypto/hash/verify
   ↓
5. Generate RSA Keys
   POST /crypto/rsa/keys
   ↓
6. Sign Document
   POST /crypto/sign
   ↓
7. Verify Signature
   POST /crypto/verify
   ↓
8. Encrypt Data
   POST /crypto/aes/encrypt
   ↓
9. Decrypt Data
   POST /crypto/aes/decrypt
   ↓
10. Issue Certificate
    POST /crypto/certificates
    ↓
11. Validate Certificate
    POST /crypto/ca/validate
    ↓
12. Revoke Certificate
    POST /crypto/ca/revoke
```

---

## 📊 Resumen de Endpoints

| Categoría | Método | Endpoint | Descripción |
|-----------|--------|----------|-------------|
| Health | GET | `/health` | Verifica disponibilidad del servidor |
| Health | GET | `/health/db` | Verifica conexión a base de datos |
| Hash | POST | `/crypto/hash` | Genera SHA-256 |
| Hash | POST | `/crypto/hash/verify` | Verifica SHA-256 |
| RSA | POST | `/crypto/rsa/keys` | Genera claves RSA-4096 |
| Firma | POST | `/crypto/sign` | Firma con RSA privada |
| Firma | POST | `/crypto/verify` | Verifica firma con RSA pública |
| AES | POST | `/crypto/aes/encrypt` | Cifra con AES-256-GCM |
| AES | POST | `/crypto/aes/decrypt` | Descifra AES-256-GCM |
| Certificados | POST | `/crypto/certificates` | Emite certificado digital |
| Certificados | POST | `/crypto/ca/validate` | Valida certificado |
| Certificados | POST | `/crypto/ca/revoke` | Revoca certificado |

---

## 💡 Tips para Postman

### Crear un Environment
1. Haz clic en **"Environments"** en la izquierda
2. Click **"+"** → **"Create a new environment"**
3. Nombra como: `Crypto-API-Local`
4. Agrega variables:
   - `base_url`: `http://localhost:8000`
   - `crypto_url`: `http://localhost:8000/crypto`

### Usar Variables en las Requests
- **URL:** `{{base_url}}/health`
- **Body:** `"data": "{{base64_data}}"`

### Encadenamiento de Requests
En la sección **Tests** de una respuesta, agrega:
```javascript
if (pm.response.code === 200) {
    var jsonData = pm.response.json();
    pm.environment.set("variable_name", jsonData.field_name);
}
```

### Documentación Automática
Tu API tiene **Swagger/OpenAPI** en: http://localhost:8000/docs
Puedes exportar directamente desde ahí a Postman.

---

## 🚀 Iniciando el Backend

### PowerShell (Windows)
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Bash (Linux/Mac)
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Docker Compose (Recomendado)
```bash
cp .env.example .env
docker compose up --build
```

El servidor estará disponible en: **http://localhost:8000**

---

## ✅ Checklist de Pruebas

- [ ] Health check retorna `"status": "ok"`
- [ ] Database health check retorna `"database": "ok"`
- [ ] Hash SHA-256 genera hash correctamente (64 caracteres hexadecimales)
- [ ] Verificación de hash retorna `"valid": true`
- [ ] Generación de claves RSA retorna par válido
- [ ] Firma digital genera firma correctamente
- [ ] Verificación de firma retorna `"valid": true`
- [ ] Cifrado AES retorna `ciphertext`, `iv` y `tag`
- [ ] Descifrado AES retorna el texto original en Base64
- [ ] Emisión de certificado retorna certificado PEM válido
- [ ] Validación de certificado retorna `"valid": true`
- [ ] Revocación de certificado retorna estado `"revoked"`

---

## 🔗 Referencias Útiles

- **FastAPI Docs:** https://fastapi.tiangolo.com/
- **Postman Docs:** https://learning.postman.com/
- **Base64 Encoder/Decoder:** https://www.base64encode.org/
- **Cryptography Library:** https://cryptography.io/
- **OpenSSL Commands:** https://www.openssl.org/docs/

---

## 📝 Notas Importantes

1. **Base64 Encoding:** Todos los datos sensibles (plaintext, data, etc.) deben estar en **Base64** en las requests
2. **Claves Privadas:** Nunca compartas tus claves privadas. Son solo para firmar documentos
3. **Clave AES:** Si no proporcionas clave en encrypt, el servidor la genera. Guarda la respuesta completa para poder descifrar
4. **Certificados:** Los certificados emitidos son auto-firmados por la CA simulada
5. **Seguridad:** Este es un proyecto educativo. No uses en producción sin auditoría de seguridad

