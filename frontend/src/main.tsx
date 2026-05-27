import React from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

function App() {
  return (
    <main className="app-shell">
      <section className="panel">
        <p className="eyebrow">Ingenieria de Seguridad del Software</p>
        <h1>Plataforma Web Segura de Firma Digital</h1>
        <p>
          Base inicial para gestionar usuarios, documentos, certificados,
          firmas digitales, cifrado y validacion criptografica.
        </p>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
