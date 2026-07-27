from io import BytesIO
from pathlib import Path
from zipfile import BadZipFile, ZipFile


ALLOWED_EXTENSIONS = {".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg"}
CANONICAL_MIME_TYPES = {
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".txt": "text/plain",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}


def validate_document(filename: str, content: bytes) -> tuple[str, str]:
    """Validate extension and file signature; return sanitized name and MIME type."""
    safe_name = filename.replace("\\", "_").replace("/", "_")[:255]
    extension = Path(safe_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Formato no permitido. Use PDF, DOCX, TXT, PNG, JPG o JPEG")

    valid = False
    if extension == ".pdf":
        valid = content.startswith(b"%PDF-")
    elif extension == ".png":
        valid = content.startswith(b"\x89PNG\r\n\x1a\n")
    elif extension in {".jpg", ".jpeg"}:
        valid = content.startswith(b"\xff\xd8\xff") and content.endswith(b"\xff\xd9")
    elif extension == ".txt":
        try:
            content.decode("utf-8")
            valid = b"\x00" not in content
        except UnicodeDecodeError:
            valid = False
    elif extension == ".docx":
        try:
            with ZipFile(BytesIO(content)) as archive:
                names = set(archive.namelist())
                valid = "[Content_Types].xml" in names and any(
                    name.startswith("word/") for name in names
                )
        except BadZipFile:
            valid = False

    if not valid:
        raise ValueError("El contenido no corresponde al formato indicado o está dañado")
    return safe_name, CANONICAL_MIME_TYPES[extension]
