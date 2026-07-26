import React, { FormEvent, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./styles.css";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
type User = { id:number; username:string; email:string; full_name:string; role:string; active:boolean };
type Document = { id:number; filename:string; sha256:string; signature?:string; created_at:string };
type Certificate = { id:number; subject_cn:string; serial_number:string; revoked:boolean; certificate_pem:string };
type Tab = "inicio"|"documentos"|"criptografia"|"certificados"|"usuarios"|"auditoria";

async function request(path:string, options:RequestInit={}, token="") {
  const headers = new Headers(options.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (!(options.body instanceof FormData)) headers.set("Content-Type", "application/json");
  const response = await fetch(`${API}${path}`, {...options, headers});
  if (!response.ok) {
    const body = await response.json().catch(()=>({detail:"Error de comunicación"}));
    throw new Error(body.detail || `Error ${response.status}`);
  }
  if (response.status === 204) return null;
  return response.json();
}
const toB64 = (text:string) => btoa(unescape(encodeURIComponent(text)));
const fromB64 = (text:string) => decodeURIComponent(escape(atob(text)));

function Auth({onLogin}:{onLogin:(token:string,user:User)=>void}) {
  const [register,setRegister]=useState(false); const [error,setError]=useState(""); const [busy,setBusy]=useState(false);
  async function submit(e:FormEvent<HTMLFormElement>) {
    e.preventDefault(); setBusy(true); setError(""); const f=new FormData(e.currentTarget);
    try {
      if(register) {
        await request("/api/auth/register",{method:"POST",body:JSON.stringify({username:f.get("username"),email:f.get("email"),full_name:f.get("full_name"),password:f.get("password")})});
      }
      const data=await request("/api/auth/login",{method:"POST",body:JSON.stringify({username:f.get("username"),password:f.get("password")})});
      onLogin(data.access_token,data.user);
    } catch(err) { setError((err as Error).message); } finally {setBusy(false)}
  }
  return <main className="auth-page"><section className="brand-panel"><div className="brand-mark">S</div><p className="eyebrow">ESPE · Ingeniería de Seguridad</p><h1>La confianza digital,<br/>construida con evidencia.</h1><p className="lead">Firma documentos, verifica su integridad y administra certificados desde una plataforma diseñada con seguridad por defecto.</p><div className="trust"><span>SHA-256</span><span>AES-256-GCM</span><span>RSA-PSS</span><span>X.509</span></div></section><section className="auth-card"><p className="eyebrow">{register?"Nueva cuenta":"Acceso seguro"}</p><h2>{register?"Crear una cuenta":"Bienvenido de vuelta"}</h2><p className="muted">{register?"El primer usuario registrado será administrador.":"Ingresa tus credenciales para continuar."}</p><form onSubmit={submit}>{register&&<><label>Nombre completo<input name="full_name" placeholder="Nombre y apellido"/></label><label>Correo electrónico<input name="email" type="email" required placeholder="usuario@espe.edu.ec"/></label></>}<label>Usuario<input name="username" required minLength={3} autoComplete="username" placeholder="usuario"/></label><label>Contraseña<input name="password" type="password" required minLength={10} autoComplete={register?"new-password":"current-password"} placeholder="Mínimo 10 caracteres"/></label>{error&&<p className="alert error">{error}</p>}<button className="primary" disabled={busy}>{busy?"Procesando…":register?"Registrar e ingresar":"Ingresar"}</button></form><button className="link" onClick={()=>{setRegister(!register);setError("")}}>{register?"Ya tengo una cuenta":"Crear una cuenta"}</button></section></main>
}

function App() {
  const [token,setToken]=useState(localStorage.getItem("token")||""); const [user,setUser]=useState<User|null>(null);
  const [tab,setTab]=useState<Tab>("inicio"); const [docs,setDocs]=useState<Document[]>([]); const [certs,setCerts]=useState<Certificate[]>([]);
  const [users,setUsers]=useState<User[]>([]); const [logs,setLogs]=useState<any[]>([]); const [message,setMessage]=useState("");
  const [keys,setKeys]=useState({private_key:"",public_key:""}); const [cryptoOut,setCryptoOut]=useState<any>(null);
  const api=(p:string,o:RequestInit={})=>request(p,o,token);
  useEffect(()=>{if(token) api("/api/auth/me").then(setUser).catch(logout)},[token]);
  useEffect(()=>{if(!user)return; refresh();},[user,tab]);
  function login(t:string,u:User){localStorage.setItem("token",t);setToken(t);setUser(u)}
  function logout(){localStorage.removeItem("token");setToken("");setUser(null)}
  async function refresh(){try{if(tab==="documentos")setDocs(await api("/api/documents"));if(tab==="certificados")setCerts(await api("/api/certificates"));if(tab==="usuarios"&&user?.role==="admin")setUsers(await api("/api/users"));if(tab==="auditoria"&&user?.role==="admin")setLogs(await api("/api/audit"));}catch(e){setMessage((e as Error).message)}}
  async function action(fn:()=>Promise<any>,ok:string){try{const value=await fn();setMessage(ok);await refresh();return value}catch(e){setMessage((e as Error).message)}}
  if(!token||!user)return <Auth onLogin={login}/>;
  const adminNav:[Tab,string,string][] = [["usuarios","Usuarios","♙"],["auditoria","Auditoría","◎"]];
  const nav:[Tab,string,string][]=[["inicio","Resumen","⌂"],["documentos","Documentos","▤"],["criptografia","Criptografía","⌘"],["certificados","Certificados","◇"],...(user.role==="admin"?adminNav:[])];
  return <div className="shell"><aside><div className="logo"><b>S</b><span>SecureSign<small>Plataforma criptográfica</small></span></div><nav>{nav.map(([id,label,icon])=><button key={id} className={tab===id?"active":""} onClick={()=>{setTab(id);setMessage("")}}><i>{icon}</i>{label}</button>)}</nav><div className="side-status"><span className="dot"/>Servicios operativos<small>Conexión protegida</small></div></aside><main><header><div><p className="eyebrow">Panel de control</p><h2>{nav.find(n=>n[0]===tab)?.[1]}</h2></div><div className="profile"><span>{user.full_name||user.username}<small>{user.role==="admin"?"Administrador":"Usuario"}</small></span><b>{user.username[0].toUpperCase()}</b><button title="Cerrar sesión" onClick={logout}>↪</button></div></header>{message&&<div className="toast" onClick={()=>setMessage("")}>{message}<b>×</b></div>}
  {tab==="inicio"&&<Dashboard user={user} go={setTab}/>}
  {tab==="documentos"&&<Documents docs={docs} api={api} action={action} keys={keys}/>}
  {tab==="criptografia"&&<Crypto api={api} keys={keys} setKeys={setKeys} out={cryptoOut} setOut={setCryptoOut} action={action}/>}
  {tab==="certificados"&&<Certificates certs={certs} keys={keys} api={api} action={action}/>}
  {tab==="usuarios"&&<Users users={users} api={api} action={action}/>}
  {tab==="auditoria"&&<Audit logs={logs}/>}
  </main></div>
}

function Dashboard({user,go}:{user:User;go:(t:Tab)=>void}) {return <section className="content"><div className="hero"><div><p className="eyebrow">Centro de confianza digital</p><h1>Hola, {user.full_name?.split(" ")[0]||user.username}.</h1><p>Protege la autenticidad, confidencialidad e integridad de tus documentos en un solo lugar.</p><button className="primary compact" onClick={()=>go("documentos")}>Subir documento →</button></div><div className="shield">✓<span>Protección activa</span></div></div><div className="section-title"><div><h3>Operaciones principales</h3><p>Herramientas criptográficas listas para usar</p></div></div><div className="cards">{[["documentos","Firmar documentos","Firma RSA-PSS y verificación de alteraciones","01"],["criptografia","Cifrar información","Cifrado autenticado AES-256-GCM","02"],["certificados","Gestionar certificados","Emisión, validación y revocación X.509","03"]].map(([t,h,p,n])=><button className="feature" onClick={()=>go(t as Tab)} key={t}><span>{n}</span><h3>{h}</h3><p>{p}</p><b>Explorar →</b></button>)}</div><div className="security-strip"><b>Seguridad en cada operación</b><span>● PBKDF2 · 600.000 iteraciones</span><span>● Sesiones JWT con expiración</span><span>● Auditoría de eventos</span></div></section>}

function Documents({docs,api,action,keys}:{docs:Document[];api:any;action:any;keys:any}) {
  async function upload(e:FormEvent<HTMLFormElement>){e.preventDefault();const form=e.currentTarget;const body=new FormData(form);await action(()=>api("/api/documents",{method:"POST",body}),"Documento cargado");form.reset()}
  async function signDoc(id:number){if(!keys.private_key)return action(()=>Promise.reject(new Error("Genera primero un par de claves en Criptografía")),"");const body=new FormData();body.set("private_key",keys.private_key);return action(()=>api(`/api/documents/${id}/sign`,{method:"POST",body}),"Documento firmado correctamente")}
  return <section className="content"><div className="toolbar"><div><h3>Repositorio seguro</h3><p>Máximo 5 MB por archivo</p></div><form onSubmit={upload} className="upload"><input name="file" type="file" required/><button className="primary compact">Subir archivo</button></form></div><div className="table-card"><table><thead><tr><th>Documento</th><th>Huella SHA-256</th><th>Estado</th><th>Acciones</th></tr></thead><tbody>{docs.map(d=><tr key={d.id}><td><b>{d.filename}</b><small>{new Date(d.created_at).toLocaleString()}</small></td><td><code>{d.sha256.slice(0,18)}…</code></td><td><span className={d.signature?"pill good":"pill"}>{d.signature?"Firmado":"Sin firma"}</span></td><td className="actions"><button onClick={()=>signDoc(d.id)}>Firmar</button><button onClick={()=>action(()=>api(`/api/documents/${d.id}/verify`,{method:"POST"}),"Firma válida")}>Verificar</button><a href={`${API}/api/documents/${d.id}/download`} onClick={e=>{e.preventDefault();fetch(`${API}/api/documents/${d.id}/download`,{headers:{Authorization:`Bearer ${localStorage.getItem("token")}`}}).then(r=>r.blob()).then(b=>{const a=document.createElement("a");a.href=URL.createObjectURL(b);a.download=d.filename;a.click()})}}>Descargar</a><button className="danger" onClick={()=>action(()=>api(`/api/documents/${d.id}`,{method:"DELETE"}),"Documento eliminado")}>Eliminar</button></td></tr>)}</tbody></table>{!docs.length&&<Empty text="Todavía no hay documentos"/>}</div></section>
}

function Crypto({api,keys,setKeys,out,setOut,action}:{api:any;keys:any;setKeys:any;out:any;setOut:any;action:any}) {
  const [text,setText]=useState(""); const [expected,setExpected]=useState(""); const [aes,setAes]=useState<any>(null);
  return <section className="content"><div className="grid2"><div className="tool-card"><p className="number">01 · INTEGRIDAD</p><h3>Huella SHA-256</h3><textarea value={text} onChange={e=>setText(e.target.value)} placeholder="Texto para calcular o verificar…"/><input value={expected} onChange={e=>setExpected(e.target.value)} placeholder="Hash esperado (opcional)"/><button className="primary compact" onClick={async()=>{const r=await action(()=>api(expected?"/crypto/hash/verify":"/crypto/hash",{method:"POST",body:JSON.stringify(expected?{data:toB64(text),expected_hash:expected}:{data:toB64(text)})}),"Operación completada");if(r)setOut(r)}}>Procesar</button></div><div className="tool-card"><p className="number">02 · CLAVES</p><h3>Par RSA-4096</h3><p>Genera claves para firma digital y certificados. La clave privada permanece en tu navegador.</p><button className="primary compact" onClick={async()=>{const r=await action(()=>api("/crypto/rsa/keys",{method:"POST"}),"Claves generadas");if(r){setKeys(r);setOut({public_key:r.public_key})}}}>Generar claves</button><span className={keys.private_key?"pill good":"pill"}>{keys.private_key?"Claves disponibles":"Sin claves"}</span></div><div className="tool-card"><p className="number">03 · CONFIDENCIALIDAD</p><h3>AES-256-GCM</h3><textarea value={text} onChange={e=>setText(e.target.value)} placeholder="Texto para cifrar…"/><button onClick={async()=>{const r=await action(()=>api("/crypto/aes/encrypt",{method:"POST",body:JSON.stringify({plaintext:toB64(text)})}),"Texto cifrado");if(r){setAes(r);setOut(r)}}} className="primary compact">Cifrar</button>{aes&&<button onClick={async()=>{const r=await action(()=>api("/crypto/aes/decrypt",{method:"POST",body:JSON.stringify(aes)}),"Texto descifrado");if(r)setOut({plaintext:fromB64(r.plaintext)})}}>Descifrar resultado</button>}</div><div className="tool-card output"><p className="number">RESULTADO</p><h3>Salida de la operación</h3><pre>{out?JSON.stringify(out,null,2):"Los resultados aparecerán aquí."}</pre></div></div></section>
}

function Certificates({certs,keys,api,action}:{certs:Certificate[];keys:any;api:any;action:any}) {const [cn,setCn]=useState("");return <section className="content"><div className="toolbar"><div><h3>Autoridad Certificadora</h3><p>Certificados X.509 firmados por la CA simulada</p></div><form className="inline" onSubmit={async e=>{e.preventDefault();if(!keys.public_key)return action(()=>Promise.reject(new Error("Genera primero claves RSA")),"");await action(()=>api("/api/certificates",{method:"POST",body:JSON.stringify({subject_cn:cn,public_key_pem:keys.public_key,subject_country:"EC"})}),"Certificado emitido");setCn("")}}><input value={cn} onChange={e=>setCn(e.target.value)} required placeholder="Nombre común (CN)"/><button className="primary compact">Emitir</button></form></div><div className="cards">{certs.map(c=><article className="cert" key={c.id}><div className="cert-icon">◇</div><span className={c.revoked?"pill bad":"pill good"}>{c.revoked?"Revocado":"Vigente"}</span><h3>{c.subject_cn}</h3><p>Serie</p><code>{c.serial_number.slice(0,24)}…</code><div className="actions"><button onClick={()=>action(()=>api(`/api/certificates/${c.id}/validate`,{method:"POST"}),"Certificado validado")}>Validar</button><button className="danger" disabled={c.revoked} onClick={()=>action(()=>api(`/api/certificates/${c.id}`,{method:"DELETE"}),"Certificado revocado")}>Revocar</button></div></article>)}</div>{!certs.length&&<Empty text="No se han emitido certificados"/>}</section>}
function Users({users,api,action}:{users:User[];api:any;action:any}) {return <section className="content"><div className="table-card"><table><thead><tr><th>Usuario</th><th>Correo</th><th>Rol</th><th>Estado</th><th></th></tr></thead><tbody>{users.map(u=><tr key={u.id}><td><b>{u.full_name||u.username}</b><small>@{u.username}</small></td><td>{u.email}</td><td>{u.role}</td><td><span className={u.active?"pill good":"pill bad"}>{u.active?"Activo":"Inactivo"}</span></td><td><button className="danger" disabled={!u.active} onClick={()=>action(()=>api(`/api/users/${u.id}`,{method:"DELETE"}),"Usuario desactivado")}>Desactivar</button></td></tr>)}</tbody></table></div></section>}
function Audit({logs}:{logs:any[]}) {return <section className="content"><div className="table-card"><table><thead><tr><th>Fecha</th><th>Evento</th><th>Resultado</th><th>Detalle</th></tr></thead><tbody>{logs.map(l=><tr key={l.id}><td>{new Date(l.timestamp).toLocaleString()}</td><td><code>{l.tipo_evento}</code></td><td><span className={l.resultado==="ÉXITO"?"pill good":"pill bad"}>{l.resultado}</span></td><td>{l.detalle}</td></tr>)}</tbody></table></div></section>}
function Empty({text}:{text:string}){return <div className="empty"><b>◇</b><p>{text}</p></div>}
createRoot(document.getElementById("root")!).render(<React.StrictMode><App/></React.StrictMode>);
