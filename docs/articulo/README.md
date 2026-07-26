# Artículo IEEE

El manuscrito usa `IEEEtran` y BibTeX. Antes de entregar, reemplace los nombres y
correos de los autores en `articulo.tex`.

Compilación:

```bash
pdflatex articulo
bibtex articulo
pdflatex articulo
pdflatex articulo
```

Los valores experimentales proceden de `reports/metrics/summary.txt` y pueden
regenerarse desde `backend` con:

```bash
python scripts/benchmark.py
```
