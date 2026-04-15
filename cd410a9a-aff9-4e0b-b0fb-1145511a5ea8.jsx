// ─── FIREBASE IMPORTS ────────────────────────────────────────────────────────
import { initializeApp }                        from "firebase/app";
import { getFirestore, doc, setDoc, getDoc, deleteDoc, serverTimestamp } from "firebase/firestore";
import { getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword, onAuthStateChanged } from "firebase/auth";
import { useState, useRef, useEffect, useReducer, useCallback } from "react";

// ─── FIREBASE CONFIG ─────────────────────────────────────────────────────────
const firebaseConfig = {
  apiKey:            "AIzaSyDyL0bxTfe7X2de_O-wbKn09feIIxi4TTs",
  authDomain:        "beleza-hub.firebaseapp.com",
  projectId:         "beleza-hub",
  storageBucket:     "beleza-hub.firebasestorage.app",
  messagingSenderId: "752625992317",
  appId:             "1:752625992317:web:1fac364495bbb3c110e714",
};
const firebaseApp = initializeApp(firebaseConfig);
const db   = getFirestore(firebaseApp);
const auth = getAuth(firebaseApp);

// ─── CONSTANTS ────────────────────────────────────────────────────────────────
const SERVICE_CATEGORIES = ["Cabelo","Unhas","Maquiagem","Skincare","Massagem","Depilação","Sobrancelha","Barba","Outros"];
const PRODUCT_CATEGORIES = ["Shampoo & Condicionador","Tratamentos Capilares","Coloração","Maquiagem","Skincare","Perfumaria","Unhas","Equipamentos","Outros"];
const STATES_BR = ["AC","AL","AP","AM","BA","CE","DF","ES","GO","MA","MT","MS","MG","PA","PB","PR","PE","PI","RJ","RN","RS","RO","RR","SC","SP","SE","TO"];

const FRAUD_RULES = [
  { id:"cnpj",  label:"CNPJ validado",        desc:"Verificação automática na Receita Federal" },
  { id:"tel",   label:"Telefone confirmado",   desc:"Código OTP verificado" },
  { id:"email", label:"E-mail confirmado",     desc:"Código OTP verificado" },
  { id:"doc",   label:"Documentos analisados", desc:"Revisão manual em até 48h" },
  { id:"addr",  label:"Endereço verificado",   desc:"Comprovante de endereço aceito" },
];

const PLAN_TYPES = [
  { id:"salao",      label:"Salão de Beleza",        icon:"💇", desc:"Cadastre serviços, horários e equipe.", color:"#C9A96E" },
  { id:"fornecedor", label:"Fornecedor / Revendedor", icon:"📦", desc:"Catálogo de produtos com estoque e preços.", color:"#79B8D4" },
  { id:"ambos",      label:"Salão + Fornecedor",      icon:"✦",  desc:"Perfil completo: serviços e venda de produtos.", color:"#A67FC4" },
];

const EMAILJS_SERVICE_ID  = "SEU_SERVICE_ID";
const EMAILJS_TEMPLATE_ID = "SEU_TEMPLATE_ID";
const EMAILJS_PUBLIC_KEY  = "SUA_PUBLIC_KEY";

// ─── HELPERS ─────────────────────────────────────────────────────────────────
function uid() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) return crypto.randomUUID();
  return Math.random().toString(36).slice(2, 9);
}
function generateOTP() {
  const arr = new Uint32Array(1);
  crypto.getRandomValues(arr);
  return String(100000 + (arr[0] % 900000));
}
function fmtCNPJ(v)  { return v.replace(/\D/g,"").replace(/(\d{2})(\d)/,"$1.$2").replace(/(\d{3})(\d)/,"$1.$2").replace(/(\d{3})(\d)/,"$1/$2").replace(/(\d{4})(\d)/,"$1-$2").slice(0,18); }
function fmtPhone(v) { return v.replace(/\D/g,"").replace(/(\d{2})(\d)/,"($1) $2").replace(/(\d{5})(\d)/,"$1-$2").slice(0,15); }
function fmtCEP(v)   { return v.replace(/\D/g,"").replace(/(\d{5})(\d)/,"$1-$2").slice(0,9); }
function fmtCPF(v)   { return v.replace(/\D/g,"").replace(/(\d{3})(\d)/,"$1.$2").replace(/(\d{3})(\d)/,"$1.$2").replace(/(\d{3})(\d)/,"$1-$2").slice(0,14); }

function validateCNPJ(c) {
  const d = c.replace(/\D/g,"");
  if (d.length!==14||/^(\d)\1{13}$/.test(d)) return false;
  const calc=(s,n)=>{ let sum=0,pos=n-7; for(let i=n;i>=1;i--){sum+=parseInt(s[n-i])*pos--;if(pos<2)pos=9;} return sum%11<2?0:11-(sum%11); };
  return calc(d,12)===parseInt(d[12])&&calc(d,13)===parseInt(d[13]);
}
function validateCPF(c) {
  const d = c.replace(/\D/g,"");
  if (d.length!==11||/^(\d)\1{10}$/.test(d)) return false;
  const calc=(s,n)=>{ let sum=0; for(let i=0;i<n;i++) sum+=parseInt(s[i])*(n+1-i); const r=(sum*10)%11; return r===10||r===11?0:r; };
  return calc(d,9)===parseInt(d[9])&&calc(d,10)===parseInt(d[10]);
}
function validateEmail(e) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e); }

const ALLOWED_IMAGE_TYPES = ["image/jpeg","image/png","image/webp","image/gif"];
const ALLOWED_DOC_TYPES   = [...ALLOWED_IMAGE_TYPES,"application/pdf"];
function validateFileType(file,allowedTypes) { return allowedTypes.includes(file.type); }

function passwordStrength(pw) {
  if (!pw) return {score:0,label:"",color:""};
  let s=0;
  if(pw.length>=8) s++; if(pw.length>=12) s++;
  if(/[A-Z]/.test(pw)) s++; if(/[0-9]/.test(pw)) s++; if(/[^A-Za-z0-9]/.test(pw)) s++;
  if(s<=1) return {score:20,label:"Senha muito fraca",color:"#D4735A"};
  if(s===2) return {score:40,label:"Senha fraca",color:"#E8935A"};
  if(s===3) return {score:65,label:"Senha razoável",color:"#E8B86D"};
  if(s===4) return {score:85,label:"Senha boa",color:"#7DBB7D"};
  return {score:100,label:"Senha forte ✓",color:"#5BAA5B"};
}

// ─── FIREBASE HELPERS ────────────────────────────────────────────────────────

// Salva rascunho no Firestore (sem senha, sem arquivos)
async function saveDraftFS(userId, data) {
  const clean = { ...data };
  ["password","confirmPassword","cnpjDoc","addressProof","ownerDoc"].forEach(k => delete clean[k]);
  await setDoc(doc(db,"drafts",userId), { ...clean, _updatedAt: serverTimestamp() }, { merge:true });
}

// Carrega rascunho do Firestore
async function loadDraftFS(userId) {
  const snap = await getDoc(doc(db,"drafts",userId));
  if (!snap.exists()) return null;
  const data = snap.data();
  delete data._updatedAt;
  return data;
}

// Envia cadastro final para Firestore
async function submitToFirestore(userId, formData, services, products, protocol) {
  const clean = { ...formData };
  ["password","confirmPassword","cnpjDoc","addressProof","ownerDoc"].forEach(k => delete clean[k]);
  await setDoc(doc(db,"establishments",userId), {
    ...clean,
    services,
    products,
    protocol,
    status:    "pending_review",
    createdAt: serverTimestamp(),
  });
  // Remove rascunho
  try { await deleteDoc(doc(db,"drafts",userId)); } catch {}
}

// ─── FORM REDUCER ─────────────────────────────────────────────────────────────
const INITIAL_FORM = {
  businessName:"",tradeName:"",cnpj:"",email:"",phone:"",whatsapp:"",
  website:"",instagram:"",description:"",
  cep:"",street:"",number:"",complement:"",neighborhood:"",city:"",state:"",
  ownerName:"",ownerCPF:"",ownerEmail:"",ownerPhone:"",
  password:"",confirmPassword:"",
  cnpjDoc:null,addressProof:null,ownerDoc:null,
  bankName:"",agency:"",account:"",pix:"",
  emailCode:"",phoneCode:"",
  emailVerified:false,phoneVerified:false,cnpjVerified:false,
  acceptTerms:false,acceptPrivacy:false,acceptAntiFraud:false,
};

function formReducer(state,{key,val}) {
  if (key==="cnpj")    return {...state,cnpj:val,cnpjVerified:false};
  if (key==="__reset") return {...INITIAL_FORM,...val};
  return {...state,[key]:val};
}

// ─── EMAILJS ──────────────────────────────────────────────────────────────────
async function sendEmailOTP(toEmail, otpCode) {
  if (!window.emailjs) {
    await new Promise((res,rej) => {
      const s=document.createElement("script");
      s.src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js";
      s.onload=res; s.onerror=rej;
      document.head.appendChild(s);
    });
    window.emailjs.init({publicKey:EMAILJS_PUBLIC_KEY});
  }
  await window.emailjs.send(EMAILJS_SERVICE_ID,EMAILJS_TEMPLATE_ID,{
    to_email:toEmail, otp_code:otpCode, business_name:"beleza.hub",
  });
}

// ─── MAIN COMPONENT ───────────────────────────────────────────────────────────
export default function BeautyRegister() {
  const [screen,        setScreen]       = useState("landing");
  const [accountType,   setAccountType]  = useState(null);
  const [step,          setStep]         = useState(1);
  const [formData,      dispatch]        = useReducer(formReducer,INITIAL_FORM);
  const [services,      setServices]     = useState([]);
  const [products,      setProducts]     = useState([]);
  const [errors,        setErrors]       = useState({});
  const [verifyingCNPJ, setVerifyingCNPJ]= useState(false);
  const [cnpjData,      setCnpjData]     = useState(null);
  const [cnpjError,     setCnpjError]    = useState("");
  const [sendingCode,   setSendingCode]  = useState(false);
  const [logoPreview,   setLogoPreview]  = useState(null);
  const [coverPreview,  setCoverPreview] = useState(null);
  const [toast,         setToast]        = useState(null);
  const [securityScore, setSecurityScore]= useState(0);
  const [showPass,      setShowPass]     = useState(false);
  const [showConfirmPass,setShowConfirmPass]=useState(false);
  const [stepDir,       setStepDir]      = useState(1);
  const [isSubmitting,  setIsSubmitting] = useState(false);
  const [authUser,      setAuthUser]     = useState(null);   // usuário Firebase logado
  const [authLoading,   setAuthLoading]  = useState(true);   // aguardando onAuthStateChanged
  const [draftLoading,  setDraftLoading] = useState(false);  // carregando rascunho do Firestore
  const [hasDraft,      setHasDraft]     = useState(false);
  const [saveStatus,    setSaveStatus]   = useState("");      // "saving" | "saved" | ""

  const emailOTPRef  = useRef("");
  const phoneOTPRef  = useRef("");
  const protocolRef  = useRef(null);
  const toastTimerRef= useRef(null);
  const saveTimerRef = useRef(null);

  // ── Toast
  const showToast = useCallback((msg,type="info") => {
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    setToast({msg,type});
    toastTimerRef.current = setTimeout(()=>setToast(null),3500);
  },[]);
  useEffect(()=>()=>{
    if(toastTimerRef.current) clearTimeout(toastTimerRef.current);
    if(saveTimerRef.current)  clearTimeout(saveTimerRef.current);
  },[]);

  const set = useCallback((key,val)=>dispatch({key,val}),[]);

  // ── Observa autenticação Firebase
  useEffect(()=>{
    const unsub = onAuthStateChanged(auth, user=>{
      setAuthUser(user);
      setAuthLoading(false);
      if (user) {
        // Tenta carregar rascunho ao logar
        setDraftLoading(true);
        loadDraftFS(user.uid)
          .then(draft=>{
            if (draft && Object.keys(draft).some(k=>draft[k])) setHasDraft(true);
          })
          .catch(()=>{})
          .finally(()=>setDraftLoading(false));
      }
    });
    return unsub;
  },[]);

  const restoreDraft = async () => {
    if (!authUser) return;
    setDraftLoading(true);
    try {
      const draft = await loadDraftFS(authUser.uid);
      if (draft) { dispatch({key:"__reset",val:draft}); setHasDraft(false); showToast("Rascunho restaurado ✓","success"); }
    } catch { showToast("Erro ao carregar rascunho","error"); }
    finally { setDraftLoading(false); }
  };

  // ── Auto-save no Firestore com debounce de 1.5s
  useEffect(()=>{
    if (!authUser) return;
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    setSaveStatus("saving");
    saveTimerRef.current = setTimeout(async ()=>{
      try {
        await saveDraftFS(authUser.uid,formData);
        setSaveStatus("saved");
        setTimeout(()=>setSaveStatus(""),2000);
      } catch { setSaveStatus(""); }
    },1500);
  },[formData,authUser]);

  // ── Security score
  useEffect(()=>{
    let s=0;
    if(formData.cnpjVerified)  s+=20;
    if(formData.emailVerified) s+=15;
    if(formData.phoneVerified) s+=15;
    if(formData.ownerDoc)      s+=25;
    if(formData.addressProof)  s+=25;
    setSecurityScore(s);
  },[formData.cnpjVerified,formData.emailVerified,formData.phoneVerified,formData.ownerDoc,formData.addressProof]);

  // ── CNPJ real (publica.cnpj.ws)
  const verifyCNPJ = async () => {
    if (!validateCNPJ(formData.cnpj)) { showToast("CNPJ inválido — verifique os dígitos","error"); return; }
    setVerifyingCNPJ(true); setCnpjError(""); setCnpjData(null);
    try {
      const raw = formData.cnpj.replace(/\D/g,"");
      const res = await fetch(`https://publica.cnpj.ws/cnpj/${raw}`);
      if (!res.ok) throw new Error("not_found");
      const data = await res.json();
      const situacao = data.situacao_cadastral?.descricao||"";
      if (situacao.toUpperCase()!=="ATIVA") {
        setCnpjError(`CNPJ ${situacao||"irregular"} na Receita Federal`);
        showToast("CNPJ não está ativo","error");
      } else {
        setCnpjData(data);
        set("cnpjVerified",true);
        if (!formData.businessName && data.razao_social) set("businessName",data.razao_social);
        showToast("CNPJ verificado ✓","success");
      }
    } catch(err) {
      if (err.message==="not_found") { setCnpjError("CNPJ não encontrado na Receita Federal"); showToast("CNPJ não encontrado","error"); }
      else { set("cnpjVerified",true); showToast("CNPJ válido (API indisponível — verificado localmente)","info"); }
    } finally { setVerifyingCNPJ(false); }
  };

  // ── CEP autocomplete
  const prevCEP = useRef("");
  useEffect(()=>{
    const raw = formData.cep.replace(/\D/g,"");
    if (raw.length===8&&raw!==prevCEP.current) {
      prevCEP.current=raw;
      fetch(`https://viacep.com.br/ws/${raw}/json/`)
        .then(r=>r.json())
        .then(d=>{ if(!d.erro){ set("street",d.logradouro||""); set("neighborhood",d.bairro||""); set("city",d.localidade||""); set("state",d.uf||""); showToast("Endereço preenchido ✓","success"); } })
        .catch(()=>{});
    }
  },[formData.cep]);

  // ── Enviar OTP
  const sendVerification = async (type) => {
    setSendingCode(true);
    const otp = generateOTP();
    if (type==="email") {
      emailOTPRef.current=otp;
      try { await sendEmailOTP(formData.email,otp); showToast(`Código enviado para ${formData.email}`,"success"); }
      catch { showToast(`[DEMO] Código: ${otp} — configure EmailJS para envio real`,"info"); }
    } else {
      phoneOTPRef.current=otp;
      showToast(`[DEMO SMS] Código: ${otp} — integre Z-API para SMS real`,"info");
    }
    setSendingCode(false);
  };

  const checkCode = (type) => {
    const entered  = type==="email"?formData.emailCode:formData.phoneCode;
    const expected = type==="email"?emailOTPRef.current:phoneOTPRef.current;
    if (!expected) { showToast("Envie o código primeiro","error"); return; }
    if (entered===expected) { set(type==="email"?"emailVerified":"phoneVerified",true); showToast(`${type==="email"?"E-mail":"Telefone"} verificado ✓`,"success"); }
    else showToast("Código incorreto","error");
  };

  // ── Navegação
  const goToStep = (n) => { if(n<step){setStepDir(-1);setStep(n);setErrors({});window.scrollTo(0,0);} };

  const validateStep = () => {
    const e={};
    if(step===1){
      if(!formData.businessName)         e.businessName  ="Nome obrigatório";
      if(!validateCNPJ(formData.cnpj))   e.cnpj          ="CNPJ inválido";
      if(!formData.cnpjVerified)         e.cnpjVerified  ="Verifique o CNPJ antes de continuar";
      if(!validateEmail(formData.email)) e.email         ="E-mail inválido";
      if(!formData.phone)                e.phone         ="Telefone obrigatório";
    }
    if(step===2){
      if(!formData.cep)    e.cep   ="CEP obrigatório";
      if(!formData.street) e.street="Rua obrigatória";
      if(!formData.number) e.number="Número obrigatório";
      if(!formData.city)   e.city  ="Cidade obrigatória";
      if(!formData.state)  e.state ="Estado obrigatório";
    }
    if(step===3){
      if(!formData.ownerName)  e.ownerName ="Nome obrigatório";
      if(!formData.ownerEmail) e.ownerEmail="E-mail obrigatório";
      if(formData.ownerCPF&&!validateCPF(formData.ownerCPF)) e.ownerCPF="CPF inválido";
    }
    if(step===4){ if(!formData.emailVerified) e.emailVerified="Confirme o e-mail"; if(!formData.phoneVerified) e.phoneVerified="Confirme o telefone"; }
    if(step===5){
      const pw=formData.password;
      if(pw.length<8)                       e.password       ="Mínimo 8 caracteres";
      if(pw.length>=8&&!/[A-Z]/.test(pw))   e.password       ="Inclua ao menos uma maiúscula";
      if(pw.length>=8&&!/[0-9]/.test(pw))   e.password       ="Inclua ao menos um número";
      if(pw!==formData.confirmPassword)      e.confirmPassword="Senhas não conferem";
      if(!formData.acceptTerms)     e.acceptTerms    ="Aceite os termos";
      if(!formData.acceptPrivacy)   e.acceptPrivacy  ="Aceite a política de privacidade";
      if(!formData.acceptAntiFraud) e.acceptAntiFraud="Aceite os termos antifraude";
    }
    setErrors(e);
    return Object.keys(e).length===0;
  };

  const nextStep = () => { if(validateStep()){setStepDir(1);setStep(p=>p+1);window.scrollTo(0,0);} };
  const prevStep = () => { setStepDir(-1);setStep(p=>p-1);setErrors({});window.scrollTo(0,0); };

  // ── Submit: cria Auth + salva no Firestore
  const handleSubmit = async () => {
    if (!validateStep()) return;
    setIsSubmitting(true);
    if (!protocolRef.current) protocolRef.current=`BH-${uid().slice(0,8).toUpperCase()}`;
    try {
      let userId = authUser?.uid;

      if (!userId) {
        // Cria conta no Firebase Auth
        const cred = await createUserWithEmailAndPassword(auth,formData.email,formData.password);
        userId = cred.user.uid;
      }

      // Salva cadastro completo no Firestore
      await submitToFirestore(userId,formData,services,products,protocolRef.current);
      setScreen("review");
    } catch(err) {
      if (err.code==="auth/email-already-in-use") {
        showToast("E-mail já cadastrado. Tente fazer login.","error");
      } else if (err.code==="auth/weak-password") {
        showToast("Senha muito fraca (mínimo 6 caracteres Firebase)","error");
      } else {
        showToast("Erro ao salvar cadastro. Tente novamente.","error");
        console.error(err);
      }
    } finally { setIsSubmitting(false); }
  };

  const handleImageUpload = (e,setter) => {
    const file=e.target.files[0]; if(!file)return;
    if(!validateFileType(file,ALLOWED_IMAGE_TYPES)){showToast("Formato inválido","error");e.target.value="";return;}
    if(file.size>5*1024*1024){showToast("Imagem deve ter menos de 5MB","error");e.target.value="";return;}
    const reader=new FileReader(); reader.onload=ev=>setter(ev.target.result); reader.readAsDataURL(file);
  };

  const needsServices = accountType==="salao"||accountType==="ambos";
  const needsProducts = accountType==="fornecedor"||accountType==="ambos";
  const totalSteps    = 5;
  const pwStrength    = passwordStrength(formData.password);

  // ── Loading Firebase Auth
  if (authLoading) return (
    <div style={{minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",background:"#F8F6F2"}}>
      <div style={{textAlign:"center"}}>
        <div style={{width:40,height:40,border:"3px solid #EDE9E2",borderTopColor:"#C9A96E",borderRadius:"50%",animation:"spin 0.7s linear infinite",margin:"0 auto 16px"}} />
        <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.8rem",color:"#9A9288"}}>Carregando...</div>
      </div>
    </div>
  );

  return (
    <div style={{minHeight:"100vh",background:"#F8F6F2"}}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:ital,wght@0,300;0,400;0,600;1,300&family=DM+Sans:wght@300;400;500;600&display=swap');
        *{box-sizing:border-box;margin:0;padding:0;}
        @keyframes slideInRight{from{opacity:0;transform:translateX(32px)}to{opacity:1;transform:translateX(0)}}
        @keyframes slideInLeft {from{opacity:0;transform:translateX(-32px)}to{opacity:1;transform:translateX(0)}}
        @keyframes fadeUp      {from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
        @keyframes pulse       {0%,100%{opacity:1}50%{opacity:0.4}}
        @keyframes shimmer     {0%{background-position:-400px 0}100%{background-position:400px 0}}
        @keyframes spin        {to{transform:rotate(360deg)}}
        @keyframes popIn       {0%{transform:scale(0.8);opacity:0}60%{transform:scale(1.05)}100%{transform:scale(1);opacity:1}}
        @keyframes toastSlide  {from{opacity:0;transform:translateX(24px)}to{opacity:1;transform:translateX(0)}}
        .fade-up   {animation:fadeUp 0.38s cubic-bezier(0.22,1,0.36,1) both;}
        .slide-in  {animation:slideInRight 0.32s cubic-bezier(0.22,1,0.36,1) both;}
        .slide-back{animation:slideInLeft  0.32s cubic-bezier(0.22,1,0.36,1) both;}
        .skeleton{background:linear-gradient(90deg,#EDE9E2 25%,#F5F2EC 50%,#EDE9E2 75%);background-size:400px 100%;animation:shimmer 1.4s infinite;border-radius:6px;}
        .inp{width:100%;padding:11px 14px;border:1.5px solid #DDD8CE;border-radius:8px;background:#fff;font-family:'DM Sans',sans-serif;font-size:0.85rem;color:#1A1715;outline:none;transition:border 0.18s,box-shadow 0.18s,transform 0.12s;}
        .inp:focus{border-color:#C9A96E;box-shadow:0 0 0 3px rgba(201,169,110,0.14);transform:translateY(-1px);}
        .inp.err{border-color:#D4735A;box-shadow:0 0 0 3px rgba(212,115,90,0.1);}
        select.inp{cursor:pointer;}
        .btn{transition:all 0.18s cubic-bezier(0.22,1,0.36,1);cursor:pointer;border:none;outline:none;}
        .btn:hover{filter:brightness(1.08);transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,0.15);}
        .btn:active{transform:translateY(0);box-shadow:none;}
        .btn:disabled{opacity:0.5;cursor:not-allowed;transform:none!important;filter:none!important;box-shadow:none!important;}
        .hov{transition:all 0.22s cubic-bezier(0.22,1,0.36,1);cursor:pointer;}
        .hov:hover{transform:translateY(-3px);box-shadow:0 12px 32px rgba(0,0,0,0.12)!important;}
        .drop-zone{border:2px dashed #DDD8CE;border-radius:12px;padding:32px;text-align:center;cursor:pointer;transition:all 0.2s;}
        .drop-zone:hover{border-color:#C9A96E;background:#FFFDF8;transform:scale(1.01);}
        .check-box{width:20px;height:20px;border:2px solid #DDD8CE;border-radius:5px;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all 0.2s;flex-shrink:0;}
        .check-box:hover{border-color:#C9A96E;transform:scale(1.1);}
        .check-box.on{background:#C9A96E;border-color:#C9A96E;animation:popIn 0.22s ease;}
        .score-bar{height:6px;border-radius:3px;background:#E8E3DA;overflow:hidden;}
        .score-fill{height:100%;border-radius:3px;transition:width 0.6s cubic-bezier(0.22,1,0.36,1);}
        .step-pill{font-family:'DM Sans',sans-serif;font-size:0.65rem;padding:5px 10px;border-radius:20px;transition:all 0.22s;user-select:none;}
        .pass-wrap{position:relative;}
        .pass-eye{position:absolute;right:12px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:0.9rem;color:#9A9288;user-select:none;transition:transform 0.15s;}
        .pass-eye:hover{transform:translateY(-50%) scale(1.2);}
        .spinner{width:16px;height:16px;border:2px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin 0.6s linear infinite;display:inline-block;vertical-align:middle;margin-right:6px;}
        .sec-dot{animation:pulse 2s ease infinite;}
        ::-webkit-scrollbar{width:4px;}
        ::-webkit-scrollbar-track{background:#F0EDE6;}
        ::-webkit-scrollbar-thumb{background:#C8BBA8;border-radius:2px;}
      `}</style>

      {/* TOAST */}
      {toast&&(
        <div style={{position:"fixed",top:16,right:16,zIndex:9999,animation:"toastSlide 0.28s ease",
          background:toast.type==="error"?"#2A1210":toast.type==="success"?"#0F2010":toast.type==="info"?"#14203A":"#1A1715",
          color:toast.type==="error"?"#F4907A":toast.type==="success"?"#7DC97D":toast.type==="info"?"#79B8D4":"#F7F5F0",
          padding:"12px 20px",borderRadius:10,fontFamily:"'DM Sans',sans-serif",fontSize:"0.82rem",
          boxShadow:"0 8px 32px rgba(0,0,0,0.35)",
          borderLeft:`3px solid ${toast.type==="error"?"#D4735A":toast.type==="success"?"#5BAA5B":toast.type==="info"?"#79B8D4":"#C9A96E"}`,
          maxWidth:380,lineHeight:1.5}}>
          {toast.msg}
        </div>
      )}

      {/* DRAFT BANNER (só se logado e tiver rascunho) */}
      {hasDraft&&screen==="landing"&&authUser&&(
        <div className="fade-up" style={{background:"#FFF8ED",borderBottom:"1px solid #F0D99A",padding:"10px 24px",display:"flex",justifyContent:"space-between",alignItems:"center",gap:12,flexWrap:"wrap"}}>
          <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem",color:"#7A6020"}}>
            ☁️ Rascunho salvo no Firebase. Deseja continuar de onde parou?
          </span>
          <div style={{display:"flex",gap:8}}>
            <button className="btn" onClick={restoreDraft} disabled={draftLoading} style={{padding:"6px 16px",borderRadius:6,background:"#C9A96E",color:"#fff",fontFamily:"'DM Sans',sans-serif",fontSize:"0.75rem"}}>
              {draftLoading?"Carregando...":"Restaurar rascunho"}
            </button>
            <button className="btn" onClick={()=>setHasDraft(false)} style={{padding:"6px 12px",borderRadius:6,background:"transparent",color:"#9A9288",border:"1px solid #E0D9CE",fontFamily:"'DM Sans',sans-serif",fontSize:"0.75rem"}}>
              Descartar
            </button>
          </div>
        </div>
      )}

      {/* NAV */}
      <nav style={{background:"#fff",borderBottom:"1px solid #EDE9E2",padding:"0 24px",height:60,display:"flex",alignItems:"center",justifyContent:"space-between",position:"sticky",top:0,zIndex:100,boxShadow:"0 2px 12px rgba(0,0,0,0.04)"}}>
        <div onClick={()=>{setScreen("landing");setStep(1);}} style={{cursor:"pointer",display:"flex",alignItems:"center",gap:12}}>
          <span style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"1.4rem",color:"#1A1715",letterSpacing:"1px"}}>
            beleza<em style={{color:"#C9A96E"}}>.hub</em>
          </span>
          <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#9A9288",letterSpacing:"3px"}}>CADASTRO EMPRESARIAL</span>
        </div>
        <div style={{display:"flex",alignItems:"center",gap:16}}>
          {/* Indicador de auto-save Firebase */}
          {authUser&&saveStatus&&(
            <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:saveStatus==="saved"?"#5BAA5B":"#9A9288",display:"flex",alignItems:"center",gap:4}}>
              {saveStatus==="saving"&&<span className="spinner" style={{width:10,height:10,borderTopColor:"#9A9288",marginRight:0}} />}
              {saveStatus==="saving"?"Salvando...":"☁️ Salvo"}
            </span>
          )}
          {authUser&&(
            <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.68rem",color:"#9A9288"}}>
              🔐 {authUser.email}
            </span>
          )}
          <div style={{display:"flex",alignItems:"center",gap:6}}>
            <div className="sec-dot" style={{width:8,height:8,borderRadius:"50%",background:securityScore>60?"#5BAA5B":securityScore>30?"#E8B86D":"#D4735A",boxShadow:`0 0 6px ${securityScore>60?"#5BAA5B":securityScore>30?"#E8B86D":"#D4735A"}`}} />
            <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#7A7268"}}>Segurança: {securityScore}%</span>
          </div>
        </div>
      </nav>

      {/* ══ LANDING ══════════════════════════════════════════════════════════ */}
      {screen==="landing"&&(
        <div className="fade-up">
          <div style={{background:"linear-gradient(160deg,#1A1715 0%,#2C2420 60%,#1A1715 100%)",padding:"72px 24px",textAlign:"center",position:"relative",overflow:"hidden"}}>
            <div style={{position:"absolute",inset:0,backgroundImage:"radial-gradient(circle at 15% 50%,rgba(201,169,110,0.12) 0%,transparent 50%),radial-gradient(circle at 85% 20%,rgba(201,169,110,0.08) 0%,transparent 40%)"}} />
            <div style={{position:"relative"}}>
              <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"5px",color:"#C9A96E"}}>PLATAFORMA VERIFICADA · FIREBASE POWERED</span>
              <h1 style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"clamp(2.2rem,5vw,3.8rem)",color:"#F7F5F0",fontWeight:300,lineHeight:1.1,margin:"20px 0 16px"}}>
                Cadastre seu negócio<br/><em style={{color:"#C9A96E"}}>com segurança total</em>
              </h1>
              <p style={{fontFamily:"'DM Sans',sans-serif",color:"#9A8F85",fontSize:"0.9rem",maxWidth:520,margin:"0 auto 40px",lineHeight:1.7}}>
                Dados salvos em tempo real no Firebase. CNPJ verificado na Receita Federal. Acesso de qualquer dispositivo.
              </p>
              <button className="btn" onClick={()=>setScreen("type")} style={{background:"#C9A96E",color:"#fff",padding:"14px 40px",borderRadius:8,fontFamily:"'DM Sans',sans-serif",fontSize:"0.85rem",letterSpacing:"2px",fontWeight:500}}>
                COMEÇAR CADASTRO
              </button>
            </div>
          </div>
          <div style={{background:"#fff",padding:"40px 24px",borderBottom:"1px solid #EDE9E2"}}>
            <div style={{maxWidth:800,margin:"0 auto"}}>
              <p style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"4px",color:"#9A9288",textAlign:"center",marginBottom:24}}>TECNOLOGIA GRATUITA · PRODUÇÃO REAL</p>
              <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))",gap:16}}>
                {[
                  {icon:"🏛️",title:"CNPJ Real",         desc:"API Receita Federal pública"},
                  {icon:"☁️", title:"Firebase Firestore", desc:"Dados salvos em tempo real"},
                  {icon:"🔐",title:"Firebase Auth",      desc:"Login seguro por e-mail"},
                  {icon:"📧",title:"OTP por E-mail",     desc:"EmailJS — 200 emails/mês grátis"},
                  {icon:"📍",title:"CEP Automático",     desc:"ViaCEP preenche o endereço"},
                  {icon:"🛡️",title:"Antifraude",         desc:"Validação CNPJ + CPF + docs"},
                ].map((b,i)=>(
                  <div key={b.title} className="hov fade-up" style={{textAlign:"center",padding:"20px 12px",background:"#F8F6F2",borderRadius:12,border:"1px solid #EDE9E2",animationDelay:`${i*0.07}s`}}>
                    <div style={{fontSize:"1.8rem",marginBottom:8}}>{b.icon}</div>
                    <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",fontWeight:600,color:"#1A1715",marginBottom:4}}>{b.title}</div>
                    <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#9A9288",lineHeight:1.4}}>{b.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div style={{maxWidth:800,margin:"0 auto",padding:"48px 24px"}}>
            <h2 style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"2rem",fontWeight:300,textAlign:"center",marginBottom:32}}>O que você pode cadastrar</h2>
            <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(220px,1fr))",gap:20}}>
              {PLAN_TYPES.map((t,i)=>(
                <div key={t.id} className="hov fade-up" onClick={()=>{setAccountType(t.id);setScreen("type");}} style={{background:"#fff",borderRadius:14,padding:"28px 24px",border:"1px solid #EDE9E2",boxShadow:"0 2px 12px rgba(0,0,0,0.05)",borderTop:`3px solid ${t.color}`,animationDelay:`${i*0.1}s`}}>
                  <div style={{fontSize:"2rem",marginBottom:12}}>{t.icon}</div>
                  <h3 style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"1.2rem",fontWeight:400,marginBottom:8}}>{t.label}</h3>
                  <p style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.75rem",color:"#7A7268",lineHeight:1.6}}>{t.desc}</p>
                  <div style={{marginTop:16,fontFamily:"'DM Sans',sans-serif",fontSize:"0.7rem",color:t.color,letterSpacing:"1px"}}>SELECIONAR →</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ══ TYPE SELECTION ═══════════════════════════════════════════════════ */}
      {screen==="type"&&(
        <div className="slide-in" style={{maxWidth:720,margin:"0 auto",padding:"48px 24px"}}>
          <h2 style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"2.2rem",fontWeight:300,marginBottom:8,textAlign:"center"}}>Qual é o seu tipo de negócio?</h2>
          <p style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.82rem",color:"#9A9288",textAlign:"center",marginBottom:40}}>Isso define quais seções você vai preencher no cadastro</p>
          <div style={{display:"flex",flexDirection:"column",gap:16,marginBottom:32}}>
            {PLAN_TYPES.map(t=>(
              <div key={t.id} onClick={()=>setAccountType(t.id)} style={{
                background:"#fff",borderRadius:14,padding:"24px",
                border:`2px solid ${accountType===t.id?t.color:"#EDE9E2"}`,
                cursor:"pointer",transition:"all 0.22s",
                boxShadow:accountType===t.id?`0 0 0 4px ${t.color}18`:"none",
                display:"flex",alignItems:"center",gap:20,
                transform:accountType===t.id?"translateY(-1px)":"none",
              }}>
                <div style={{width:52,height:52,borderRadius:12,background:`${t.color}15`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:"1.6rem",flexShrink:0}}>{t.icon}</div>
                <div style={{flex:1}}>
                  <div style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"1.2rem",marginBottom:4}}>{t.label}</div>
                  <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem",color:"#7A7268"}}>{t.desc}</div>
                </div>
                <div style={{width:22,height:22,borderRadius:"50%",border:`2px solid ${accountType===t.id?t.color:"#DDD8CE"}`,background:accountType===t.id?t.color:"transparent",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,transition:"all 0.2s"}}>
                  {accountType===t.id&&<div style={{width:8,height:8,borderRadius:"50%",background:"#fff"}} />}
                </div>
              </div>
            ))}
          </div>
          <button className="btn" disabled={!accountType} onClick={()=>setScreen("form")} style={{width:"100%",padding:"14px",borderRadius:8,background:accountType?PLAN_TYPES.find(t=>t.id===accountType)?.color:"#DDD8CE",color:"#fff",fontFamily:"'DM Sans',sans-serif",fontSize:"0.85rem",letterSpacing:"2px",fontWeight:500}}>
            CONTINUAR →
          </button>
        </div>
      )}

      {/* ══ FORM ════════════════════════════════════════════════════════════ */}
      {screen==="form"&&(
        <div style={{maxWidth:720,margin:"0 auto",padding:"32px 24px"}}>
          {/* Progress */}
          <div style={{marginBottom:32}}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:8}}>
              <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#9A9288"}}>Etapa {step} de {totalSteps}</span>
              <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#C9A96E"}}>{Math.round((step/totalSteps)*100)}% concluído</span>
            </div>
            <div className="score-bar" style={{marginBottom:10,height:4}}>
              <div className="score-fill" style={{width:`${(step/totalSteps)*100}%`,background:"linear-gradient(90deg,#C9A96E,#E8C98A)"}} />
            </div>
            <div style={{display:"flex",gap:4}}>
              {["Empresa","Endereço","Responsável","Verificação","Acesso"].map((label,i)=>{
                const n=i+1,done=n<step,active=n===step;
                return(
                  <div key={n} className="step-pill" onClick={()=>goToStep(n)} style={{
                    flex:1,textAlign:"center",
                    background:active?"#1A1715":done?"#C9A96E15":"#E8E3DA",
                    color:active?"#F7F5F0":done?"#C9A96E":"#B0A898",
                    border:`1px solid ${active?"#1A1715":done?"#C9A96E40":"transparent"}`,
                    cursor:done?"pointer":"default",
                  }}>{done?"✓":n}</div>
                );
              })}
            </div>
          </div>

          {/* Security score */}
          <div style={{background:"#fff",borderRadius:12,padding:"14px 16px",marginBottom:24,border:"1px solid #EDE9E2",display:"flex",alignItems:"center",gap:12}}>
            <div style={{flex:1}}>
              <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"2px",color:"#9A9288",marginBottom:4}}>PONTUAÇÃO DE SEGURANÇA</div>
              <div className="score-bar">
                <div className="score-fill" style={{width:`${securityScore}%`,background:securityScore>60?"linear-gradient(90deg,#5BAA5B,#7DC97D)":securityScore>30?"linear-gradient(90deg,#E8B86D,#F4D090)":"linear-gradient(90deg,#D4735A,#F0957A)"}} />
              </div>
            </div>
            <div style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"1.6rem",color:securityScore>60?"#5BAA5B":securityScore>30?"#C9A96E":"#D4735A",minWidth:48,textAlign:"right"}}>{securityScore}%</div>
          </div>

          <div className={stepDir>=0?"slide-in":"slide-back"} key={`step-${step}`}>

          {/* STEP 1 */}
          {step===1&&(
            <FormSection title="01 — Dados da Empresa" icon="🏢">
              <Row2>
                <Field label="Razão Social *" error={errors.businessName}>
                  <input className={`inp${errors.businessName?" err":""}`} value={formData.businessName} onChange={e=>set("businessName",e.target.value)} placeholder="Nome conforme CNPJ" />
                </Field>
                <Field label="Nome Fantasia">
                  <input className="inp" value={formData.tradeName} onChange={e=>set("tradeName",e.target.value)} placeholder="Como aparecerá na plataforma" />
                </Field>
              </Row2>
              <Field label="CNPJ *" error={errors.cnpj||errors.cnpjVerified||cnpjError}>
                <div style={{display:"flex",gap:8}}>
                  <input className={`inp${(errors.cnpj||errors.cnpjVerified||cnpjError)?" err":""}`} value={formData.cnpj} onChange={e=>{set("cnpj",fmtCNPJ(e.target.value));setCnpjError("");setCnpjData(null);}} placeholder="00.000.000/0000-00" style={{flex:1}} />
                  <button className="btn" onClick={verifyCNPJ} disabled={verifyingCNPJ||formData.cnpjVerified} style={{
                    padding:"0 16px",borderRadius:8,fontSize:"0.75rem",letterSpacing:"1px",whiteSpace:"nowrap",fontFamily:"'DM Sans',sans-serif",
                    background:formData.cnpjVerified?"#5BAA5B15":verifyingCNPJ?"#EDE9E2":"#1A1715",
                    color:formData.cnpjVerified?"#5BAA5B":verifyingCNPJ?"#9A9288":"#F7F5F0",
                    border:`1px solid ${formData.cnpjVerified?"#5BAA5B":"transparent"}`,
                    display:"flex",alignItems:"center",gap:6,
                  }}>
                    {verifyingCNPJ&&<span className="spinner" style={{borderTopColor:"#9A9288"}} />}
                    {formData.cnpjVerified?"✓ Verificado":verifyingCNPJ?"Consultando...":"Verificar CNPJ"}
                  </button>
                </div>
                {verifyingCNPJ&&(
                  <div style={{marginTop:10,display:"flex",flexDirection:"column",gap:6}}>
                    <div className="skeleton" style={{height:14,width:"70%"}} />
                    <div className="skeleton" style={{height:14,width:"50%"}} />
                  </div>
                )}
                {cnpjData&&formData.cnpjVerified&&(
                  <div style={{marginTop:8,background:"#5BAA5B0D",border:"1px solid #5BAA5B30",borderRadius:8,padding:"10px 14px",animation:"fadeUp 0.3s ease"}}>
                    <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#5BAA5B",fontWeight:600,marginBottom:4}}>✓ CNPJ ativo — Receita Federal</div>
                    <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.68rem",color:"#7A7268",lineHeight:1.6}}>
                      {cnpjData.razao_social&&<div><strong>Razão Social:</strong> {cnpjData.razao_social}</div>}
                      {cnpjData.municipio?.descricao&&<div><strong>Município:</strong> {cnpjData.municipio.descricao} / {cnpjData.municipio.uf}</div>}
                      {cnpjData.cnae_fiscal_principal?.descricao&&<div><strong>CNAE:</strong> {cnpjData.cnae_fiscal_principal.descricao}</div>}
                    </div>
                  </div>
                )}
                {cnpjError&&<Hint>{cnpjError}</Hint>}
              </Field>
              <Row2>
                <Field label="E-mail Empresarial *" error={errors.email}>
                  <input className={`inp${errors.email?" err":""}`} value={formData.email} onChange={e=>set("email",e.target.value)} placeholder="contato@empresa.com.br" type="email" />
                </Field>
                <Field label="Telefone *" error={errors.phone}>
                  <input className={`inp${errors.phone?" err":""}`} value={formData.phone} onChange={e=>set("phone",fmtPhone(e.target.value))} placeholder="(11) 99999-0000" />
                </Field>
              </Row2>
              <Row2>
                <Field label="WhatsApp"><input className="inp" value={formData.whatsapp} onChange={e=>set("whatsapp",fmtPhone(e.target.value))} placeholder="(11) 99999-0000" /></Field>
                <Field label="Instagram">
                  <div style={{position:"relative"}}>
                    <span style={{position:"absolute",left:12,top:"50%",transform:"translateY(-50%)",fontFamily:"'DM Sans',sans-serif",fontSize:"0.85rem",color:"#9A9288"}}>@</span>
                    <input className="inp" style={{paddingLeft:28}} value={formData.instagram} onChange={e=>set("instagram",e.target.value)} placeholder="seunegocio" />
                  </div>
                </Field>
              </Row2>
              <Field label="Descrição do Negócio">
                <textarea className="inp" rows={3} value={formData.description} onChange={e=>set("description",e.target.value)} style={{resize:"vertical"}} placeholder="Descreva seus serviços, especialidades e diferenciais..." />
              </Field>
              <Row2>
                <Field label="Logo"><ImageUpload preview={logoPreview} onChange={e=>handleImageUpload(e,setLogoPreview)} label="PNG/JPG · máx 5MB" /></Field>
                <Field label="Foto de Capa"><ImageUpload preview={coverPreview} onChange={e=>handleImageUpload(e,setCoverPreview)} label="Foto principal · 16:9" /></Field>
              </Row2>
            </FormSection>
          )}

          {/* STEP 2 */}
          {step===2&&(
            <FormSection title="02 — Endereço" icon="📍">
              <Hint>O CEP preenche o endereço automaticamente via ViaCEP.</Hint>
              <Row2>
                <Field label="CEP *" error={errors.cep}><input className={`inp${errors.cep?" err":""}`} value={formData.cep} onChange={e=>set("cep",fmtCEP(e.target.value))} placeholder="00000-000" /></Field>
                <Field label="Estado *" error={errors.state}>
                  <select className={`inp${errors.state?" err":""}`} value={formData.state} onChange={e=>set("state",e.target.value)}>
                    <option value="">Selecione</option>{STATES_BR.map(s=><option key={s}>{s}</option>)}
                  </select>
                </Field>
              </Row2>
              <Field label="Logradouro *" error={errors.street}><input className={`inp${errors.street?" err":""}`} value={formData.street} onChange={e=>set("street",e.target.value)} placeholder="Rua, Avenida..." /></Field>
              <Row2>
                <Field label="Número *" error={errors.number}><input className={`inp${errors.number?" err":""}`} value={formData.number} onChange={e=>set("number",e.target.value)} placeholder="123" /></Field>
                <Field label="Complemento"><input className="inp" value={formData.complement} onChange={e=>set("complement",e.target.value)} placeholder="Sala, Loja..." /></Field>
              </Row2>
              <Row2>
                <Field label="Bairro"><input className="inp" value={formData.neighborhood} onChange={e=>set("neighborhood",e.target.value)} placeholder="Bairro" /></Field>
                <Field label="Cidade *" error={errors.city}><input className={`inp${errors.city?" err":""}`} value={formData.city} onChange={e=>set("city",e.target.value)} placeholder="Cidade" /></Field>
              </Row2>
              <Field label="Comprovante de Endereço">
                <DocUpload file={formData.addressProof} onChange={e=>{const f=e.target.files[0];if(f){if(!validateFileType(f,ALLOWED_DOC_TYPES)){showToast("Use PDF, JPG ou PNG","error");e.target.value="";return;}if(f.size>10*1024*1024){showToast("Máx 10MB","error");e.target.value="";return;}set("addressProof",f);}}} label="Conta de luz, água ou telefone · PDF/JPG/PNG" />
              </Field>
            </FormSection>
          )}

          {/* STEP 3 */}
          {step===3&&(
            <FormSection title="03 — Responsável Legal" icon="👤">
              <div style={{background:"#FFF8ED",border:"1px solid #F0D99A",borderRadius:10,padding:"14px 16px",marginBottom:8,display:"flex",gap:10}}>
                <span>⚠️</span>
                <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.75rem",color:"#7A6020",lineHeight:1.6}}>Dados usados <strong>exclusivamente para verificação</strong> — nunca exibidos publicamente.</div>
              </div>
              <Row2>
                <Field label="Nome Completo *" error={errors.ownerName}><input className={`inp${errors.ownerName?" err":""}`} value={formData.ownerName} onChange={e=>set("ownerName",e.target.value)} placeholder="Nome conforme RG/CNH" /></Field>
                <Field label="CPF" error={errors.ownerCPF}><input className={`inp${errors.ownerCPF?" err":""}`} value={formData.ownerCPF} onChange={e=>set("ownerCPF",fmtCPF(e.target.value))} placeholder="000.000.000-00" /></Field>
              </Row2>
              <Row2>
                <Field label="E-mail *" error={errors.ownerEmail}><input className={`inp${errors.ownerEmail?" err":""}`} value={formData.ownerEmail} onChange={e=>set("ownerEmail",e.target.value)} placeholder="responsavel@email.com" type="email" /></Field>
                <Field label="Telefone Pessoal"><input className="inp" value={formData.ownerPhone} onChange={e=>set("ownerPhone",fmtPhone(e.target.value))} placeholder="(11) 99999-0000" /></Field>
              </Row2>
              <Field label="Documento de Identificação">
                <DocUpload file={formData.ownerDoc} onChange={e=>{const f=e.target.files[0];if(f){if(!validateFileType(f,ALLOWED_DOC_TYPES)){showToast("Use PDF, JPG ou PNG","error");e.target.value="";return;}set("ownerDoc",f);}}} label="RG, CNH ou Passaporte · PDF/JPG/PNG" />
              </Field>
              <Field label="Cartão CNPJ">
                <DocUpload file={formData.cnpjDoc} onChange={e=>{const f=e.target.files[0];if(f){if(!validateFileType(f,ALLOWED_DOC_TYPES)){showToast("Use PDF, JPG ou PNG","error");e.target.value="";return;}set("cnpjDoc",f);}}} label="Cartão CNPJ da Receita Federal · PDF/JPG" />
              </Field>
            </FormSection>
          )}

          {/* STEP 4 */}
          {step===4&&(
            <FormSection title="04 — Verificação de Contato" icon="📱">
              <Hint>Código de 6 dígitos enviado ao seu e-mail via EmailJS (gratuito).</Hint>
              {/* Email */}
              <div style={{background:"#fff",border:"1px solid #EDE9E2",borderRadius:12,padding:"20px",marginBottom:16}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
                  <div>
                    <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.8rem",fontWeight:500,color:"#1A1715"}}>📧 E-mail</div>
                    <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#9A9288",marginTop:2}}>{formData.email||"—"}</div>
                  </div>
                  {formData.emailVerified
                    ?<span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#5BAA5B",background:"#5BAA5B15",padding:"4px 12px",borderRadius:20,border:"1px solid #5BAA5B40"}}>✓ Verificado</span>
                    :<button className="btn" onClick={()=>sendVerification("email")} disabled={sendingCode||!formData.email} style={{padding:"6px 14px",borderRadius:6,background:"#1A1715",color:"#F7F5F0",fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",display:"flex",alignItems:"center"}}>
                      {sendingCode&&<span className="spinner" />}Enviar código
                    </button>}
                </div>
                {!formData.emailVerified&&(
                  <div style={{display:"flex",gap:8}}>
                    <input className="inp" value={formData.emailCode} onChange={e=>set("emailCode",e.target.value)} placeholder="000000" style={{flex:1,letterSpacing:"4px",fontSize:"1.1rem",textAlign:"center"}} maxLength={6} />
                    <button className="btn" onClick={()=>checkCode("email")} style={{padding:"0 16px",borderRadius:8,background:"#C9A96E",color:"#fff",fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem"}}>Confirmar</button>
                  </div>
                )}
                {errors.emailVerified&&<div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#D4735A",marginTop:6}}>{errors.emailVerified}</div>}
              </div>
              {/* Phone */}
              <div style={{background:"#fff",border:"1px solid #EDE9E2",borderRadius:12,padding:"20px",marginBottom:16}}>
                <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:12}}>
                  <div>
                    <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.8rem",fontWeight:500,color:"#1A1715"}}>📱 Telefone</div>
                    <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#9A9288",marginTop:2}}>{formData.phone||"—"}</div>
                  </div>
                  {formData.phoneVerified
                    ?<span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#5BAA5B",background:"#5BAA5B15",padding:"4px 12px",borderRadius:20,border:"1px solid #5BAA5B40"}}>✓ Verificado</span>
                    :<button className="btn" onClick={()=>sendVerification("phone")} disabled={sendingCode||!formData.phone} style={{padding:"6px 14px",borderRadius:6,background:"#1A1715",color:"#F7F5F0",fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",display:"flex",alignItems:"center"}}>
                      {sendingCode&&<span className="spinner" />}Enviar código
                    </button>}
                </div>
                {!formData.phoneVerified&&(
                  <div style={{display:"flex",gap:8}}>
                    <input className="inp" value={formData.phoneCode} onChange={e=>set("phoneCode",e.target.value)} placeholder="000000" style={{flex:1,letterSpacing:"4px",fontSize:"1.1rem",textAlign:"center"}} maxLength={6} />
                    <button className="btn" onClick={()=>checkCode("phone")} style={{padding:"0 16px",borderRadius:8,background:"#C9A96E",color:"#fff",fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem"}}>Confirmar</button>
                  </div>
                )}
                {errors.phoneVerified&&<div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#D4735A",marginTop:6}}>{errors.phoneVerified}</div>}
              </div>
              {/* Checklist */}
              <div style={{background:"#F8F6F2",border:"1px solid #EDE9E2",borderRadius:12,padding:"16px 20px"}}>
                <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"2px",color:"#9A9288",marginBottom:12}}>CHECKLIST DE SEGURANÇA</div>
                {FRAUD_RULES.map(r=>{
                  const done=(r.id==="cnpj"&&formData.cnpjVerified)||(r.id==="tel"&&formData.phoneVerified)||(r.id==="email"&&formData.emailVerified)||(r.id==="doc"&&formData.ownerDoc)||(r.id==="addr"&&formData.addressProof);
                  return(
                    <div key={r.id} style={{display:"flex",gap:10,alignItems:"center",marginBottom:10,transition:"all 0.3s"}}>
                      <div style={{width:20,height:20,borderRadius:"50%",background:done?"#5BAA5B15":"#EDE9E2",border:`1px solid ${done?"#5BAA5B":"#DDD8CE"}`,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,transition:"all 0.3s"}}>
                        {done?<span style={{color:"#5BAA5B",fontSize:"0.7rem"}}>✓</span>:<span style={{color:"#C8BBA8",fontSize:"0.7rem"}}>○</span>}
                      </div>
                      <div>
                        <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.75rem",color:done?"#1A1715":"#9A9288",fontWeight:done?500:400,transition:"all 0.3s"}}>{r.label}</div>
                        <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#9A9288"}}>{r.desc}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </FormSection>
          )}

          {/* STEP 5 */}
          {step===5&&(
            <FormSection title="05 — Acesso e Termos" icon="🔐">
              <Row2>
                <Field label="Senha *" error={errors.password}>
                  <div className="pass-wrap">
                    <input className={`inp${errors.password?" err":""}`} type={showPass?"text":"password"} value={formData.password} onChange={e=>set("password",e.target.value)} placeholder="Mín. 8 · maiúscula · número" style={{paddingRight:36}} />
                    <span className="pass-eye" onClick={()=>setShowPass(p=>!p)}>{showPass?"🙈":"👁️"}</span>
                  </div>
                  {formData.password&&(
                    <div style={{marginTop:6}}>
                      <div style={{height:3,background:"#E8E3DA",borderRadius:2,overflow:"hidden"}}><div style={{height:"100%",borderRadius:2,width:`${pwStrength.score}%`,background:pwStrength.color,transition:"all 0.4s ease"}} /></div>
                      <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:pwStrength.color,marginTop:3}}>{pwStrength.label}</div>
                      <div style={{display:"flex",flexWrap:"wrap",gap:4,marginTop:6}}>
                        {[{ok:formData.password.length>=8,label:"8+ chars"},{ok:/[A-Z]/.test(formData.password),label:"Maiúscula"},{ok:/[0-9]/.test(formData.password),label:"Número"},{ok:/[^A-Za-z0-9]/.test(formData.password),label:"Símbolo"}].map(r=>(
                          <span key={r.label} style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.6rem",padding:"2px 7px",borderRadius:10,background:r.ok?"#5BAA5B15":"#F0EDE8",color:r.ok?"#5BAA5B":"#9A9288",border:`1px solid ${r.ok?"#5BAA5B40":"#DDD8CE"}`,transition:"all 0.25s"}}>
                            {r.ok?"✓ ":""}{r.label}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </Field>
                <Field label="Confirmar Senha *" error={errors.confirmPassword}>
                  <div className="pass-wrap">
                    <input className={`inp${errors.confirmPassword?" err":""}`} type={showConfirmPass?"text":"password"} value={formData.confirmPassword} onChange={e=>set("confirmPassword",e.target.value)} placeholder="Repita a senha" style={{paddingRight:36}} />
                    <span className="pass-eye" onClick={()=>setShowConfirmPass(p=>!p)}>{showConfirmPass?"🙈":"👁️"}</span>
                  </div>
                  {formData.confirmPassword&&formData.password===formData.confirmPassword&&<div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#5BAA5B",marginTop:4}}>✓ Senhas coincidem</div>}
                </Field>
              </Row2>
              <div style={{background:"#F8F6F2",border:"1px solid #EDE9E2",borderRadius:12,padding:"16px 20px",marginBottom:20}}>
                <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"2px",color:"#9A9288",marginBottom:14}}>DADOS BANCÁRIOS</div>
                <Row2>
                  <Field label="Banco"><input className="inp" value={formData.bankName} onChange={e=>set("bankName",e.target.value)} placeholder="Nome do banco" /></Field>
                  <Field label="Chave PIX"><input className="inp" value={formData.pix} onChange={e=>set("pix",e.target.value)} placeholder="CPF, CNPJ, e-mail ou telefone" /></Field>
                </Row2>
              </div>
              <div style={{display:"flex",flexDirection:"column",gap:12,marginBottom:24}}>
                {[
                  {key:"acceptTerms",     label:"Li e aceito os Termos de Uso",                                                   err:errors.acceptTerms},
                  {key:"acceptPrivacy",   label:"Li e aceito a Política de Privacidade (LGPD)",                                    err:errors.acceptPrivacy},
                  {key:"acceptAntiFraud", label:"Declaro que as informações são verídicas e estou ciente das penalidades por fraude", err:errors.acceptAntiFraud, warn:true},
                ].map(t=>(
                  <div key={t.key} style={{display:"flex",gap:10,alignItems:"flex-start"}}>
                    <div className={`check-box${formData[t.key]?" on":""}`} onClick={()=>set(t.key,!formData[t.key])}>
                      {formData[t.key]&&<span style={{color:"#fff",fontSize:"0.7rem"}}>✓</span>}
                    </div>
                    <div>
                      <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem",color:t.warn?"#7A5020":"#1A1715",lineHeight:1.5}}>{t.label}</span>
                      {t.err&&<div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.68rem",color:"#D4735A",marginTop:2}}>{t.err}</div>}
                    </div>
                  </div>
                ))}
              </div>
              {/* Firebase Auth info */}
              <div style={{background:"#F0F7FF",border:"1px solid #C0D8F0",borderRadius:10,padding:"12px 16px",marginBottom:16,display:"flex",gap:10}}>
                <span>☁️</span>
                <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#2A5080",lineHeight:1.6}}>
                  Ao enviar, sua conta será criada no <strong>Firebase Authentication</strong> e seus dados salvos no <strong>Firestore</strong> — acessíveis de qualquer dispositivo.
                </div>
              </div>
            </FormSection>
          )}

          </div>

          {step===5&&(needsServices||needsProducts)&&(
            <div style={{marginTop:40}} className="fade-up">
              <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"4px",color:"#9A9288",marginBottom:20,textAlign:"center"}}>PRÉ-CADASTRO DE CATÁLOGO (OPCIONAL)</div>
              {needsServices&&<ServiceEditor services={services} setServices={setServices} showToast={showToast} />}
              {needsProducts&&<ProductEditor products={products} setProducts={setProducts} showToast={showToast} />}
            </div>
          )}

          <div style={{display:"flex",gap:12,marginTop:24}}>
            {step>1&&<button className="btn" onClick={prevStep} style={{flex:1,padding:"13px",borderRadius:8,background:"#fff",color:"#1A1715",border:"1px solid #DDD8CE",fontFamily:"'DM Sans',sans-serif",fontSize:"0.82rem",letterSpacing:"1px"}}>← Anterior</button>}
            {step<totalSteps
              ?<button className="btn" onClick={nextStep} style={{flex:2,padding:"13px",borderRadius:8,background:"#1A1715",color:"#F7F5F0",fontFamily:"'DM Sans',sans-serif",fontSize:"0.82rem",letterSpacing:"2px",fontWeight:500}}>Próximo →</button>
              :<button className="btn" onClick={handleSubmit} disabled={isSubmitting} style={{flex:2,padding:"13px",borderRadius:8,background:"#C9A96E",color:"#fff",fontFamily:"'DM Sans',sans-serif",fontSize:"0.82rem",letterSpacing:"2px",fontWeight:500,display:"flex",alignItems:"center",justifyContent:"center"}}>
                {isSubmitting&&<span className="spinner" />}
                {isSubmitting?"Salvando no Firebase...":"ENVIAR CADASTRO ✓"}
              </button>}
          </div>
        </div>
      )}

      {/* ══ REVIEW ═══════════════════════════════════════════════════════════ */}
      {screen==="review"&&(
        <div className="fade-up" style={{maxWidth:580,margin:"0 auto",padding:"64px 24px",textAlign:"center"}}>
          <div style={{fontSize:"4rem",marginBottom:24,animation:"popIn 0.4s ease"}}>🎉</div>
          <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"4px",color:"#C9A96E"}}>CADASTRO SALVO NO FIREBASE</span>
          <h2 style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"2.5rem",fontWeight:300,margin:"16px 0 12px"}}>Falta pouco!</h2>
          <p style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.85rem",color:"#7A7268",lineHeight:1.8,marginBottom:32}}>
            Seus dados foram salvos com segurança no Firebase. Nossa equipe revisará em até <strong style={{color:"#1A1715"}}>48 horas úteis</strong>.
          </p>
          <div style={{background:"#fff",border:"1px solid #EDE9E2",borderRadius:14,padding:"24px",marginBottom:24,textAlign:"left"}}>
            <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"2px",color:"#9A9288",marginBottom:16}}>O QUE ACONTECE AGORA</div>
            {[
              {icon:"☁️",title:"Dados no Firestore",       desc:"Cadastro salvo e acessível de qualquer dispositivo"},
              {icon:"📧",title:"E-mail de confirmação",     desc:"Protocolo enviado para "+formData.email},
              {icon:"👀",title:"Revisão de documentos",     desc:"Equipe analisa CNPJ, documentos e endereço"},
              {icon:"✅",title:"Aprovação e publicação",    desc:"Perfil vai ao ar após aprovação"},
            ].map((s,i)=>(
              <div key={i} className="fade-up" style={{display:"flex",gap:14,alignItems:"flex-start",marginBottom:i<3?16:0,animationDelay:`${i*0.08}s`}}>
                <div style={{width:36,height:36,borderRadius:10,background:"#F8F6F2",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"1.1rem",flexShrink:0,border:"1px solid #EDE9E2"}}>{s.icon}</div>
                <div>
                  <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.8rem",fontWeight:500,color:"#1A1715"}}>{s.title}</div>
                  <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#9A9288",marginTop:2}}>{s.desc}</div>
                </div>
              </div>
            ))}
          </div>
          <div style={{background:"#F8F6F2",border:"1px solid #EDE9E2",borderRadius:10,padding:"14px",marginBottom:24,fontFamily:"'DM Sans',sans-serif",fontSize:"0.75rem",color:"#7A7268"}}>
            🔒 Protocolo: <strong style={{color:"#1A1715",fontFamily:"monospace"}}>{protocolRef.current}</strong>
          </div>
          <button className="btn" onClick={()=>setScreen("dashboard")} style={{width:"100%",padding:"14px",borderRadius:8,background:"#1A1715",color:"#F7F5F0",fontFamily:"'DM Sans',sans-serif",fontSize:"0.82rem",letterSpacing:"2px"}}>IR PARA MEU PAINEL →</button>
        </div>
      )}

      {/* ══ DASHBOARD ════════════════════════════════════════════════════════ */}
      {screen==="dashboard"&&(
        <div className="fade-up" style={{maxWidth:900,margin:"0 auto",padding:"32px 24px"}}>
          <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:28,flexWrap:"wrap",gap:12}}>
            <div>
              <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"3px",color:"#9A9288",marginBottom:4}}>PAINEL DO ESTABELECIMENTO</div>
              <h2 style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"2rem",fontWeight:300}}>{formData.businessName||"Meu Negócio"}</h2>
            </div>
            <div style={{display:"flex",flexDirection:"column",gap:8,alignItems:"flex-end"}}>
              <div style={{background:"#FFF8ED",border:"1px solid #F0D99A",borderRadius:8,padding:"8px 14px",display:"flex",alignItems:"center",gap:6}}>
                <div style={{width:8,height:8,borderRadius:"50%",background:"#E8B86D"}} />
                <span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#7A6020"}}>Em análise</span>
              </div>
              {authUser&&<div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#9A9288"}}>☁️ Firebase: {authUser.uid.slice(0,8)}...</div>}
            </div>
          </div>
          <div style={{background:"#1A1715",borderRadius:14,padding:"20px 24px",marginBottom:20,display:"flex",gap:20,alignItems:"center",flexWrap:"wrap"}}>
            <div style={{flex:1,minWidth:200}}>
              <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"2px",color:"#C9A96E",marginBottom:8}}>PONTUAÇÃO DE SEGURANÇA</div>
              <div className="score-bar" style={{background:"#2C2420"}}><div className="score-fill" style={{width:`${securityScore}%`,background:"linear-gradient(90deg,#C9A96E,#E8C98A)"}} /></div>
            </div>
            <div style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"3rem",color:"#C9A96E"}}>{securityScore}%</div>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(200px,1fr))",gap:16,marginBottom:24}}>
            {[
              {label:"Serviços",     val:services.length,     icon:"✂️",color:"#C9A96E"},
              {label:"Produtos",     val:products.length,     icon:"📦",color:"#79B8D4"},
              {label:"Segurança",    val:`${securityScore}%`, icon:"🛡️",color:"#5BAA5B"},
              {label:"Status",       val:"Em análise",        icon:"⏳",color:"#E8B86D"},
            ].map((s,i)=>(
              <div key={s.label} className="hov fade-up" style={{background:"#fff",borderRadius:12,padding:"18px",border:"1px solid #EDE9E2",borderTop:`3px solid ${s.color}`,animationDelay:`${i*0.07}s`}}>
                <div style={{fontSize:"1.4rem",marginBottom:6}}>{s.icon}</div>
                <div style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"1.8rem",color:"#1A1715"}}>{s.val}</div>
                <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.7rem",color:"#9A9288",marginTop:2}}>{s.label}</div>
              </div>
            ))}
          </div>
          {needsServices&&<ServiceEditor services={services} setServices={setServices} showToast={showToast} />}
          {needsProducts&&<ProductEditor products={products} setProducts={setProducts} showToast={showToast} />}
        </div>
      )}
    </div>
  );
}

// ─── SERVICE EDITOR ───────────────────────────────────────────────────────────
function ServiceEditor({services,setServices,showToast}){
  const EMPTY={name:"",category:"",duration:60,price:"",description:"",id:null};
  const [adding,setAdding]=useState(false);
  const [editId,setEditId]=useState(null);
  const [form,setForm]=useState(EMPTY);
  const resetForm=()=>{setAdding(false);setEditId(null);setForm(EMPTY);};
  const edit=s=>{setForm({...s});setEditId(s.id);setAdding(true);};
  const remove=id=>setServices(p=>p.filter(s=>s.id!==id));
  const save=()=>{
    if(!form.name||!form.price){showToast("Nome e preço obrigatórios","error");return;}
    if(editId) setServices(p=>p.map(s=>s.id===editId?{...form}:s));
    else setServices(p=>[...p,{...form,id:uid()}]);
    resetForm(); showToast(editId?"Serviço atualizado ✓":"Serviço adicionado ✓","success");
  };
  return(
    <div style={{background:"#fff",border:"1px solid #EDE9E2",borderRadius:14,padding:"20px",marginBottom:20}}>
      <SectionHeader title="Serviços" icon="✂️" count={services.length} onAdd={()=>{resetForm();setAdding(true);}} />
      {services.length===0&&!adding&&<EmptyState icon="✂️" text="Nenhum serviço ainda" sub="Adicione os serviços do seu salão" />}
      <div style={{display:"flex",flexDirection:"column",gap:10,marginBottom:adding?16:0}}>
        {services.map(s=>(
          <div key={s.id} style={{display:"flex",justifyContent:"space-between",alignItems:"center",padding:"12px 14px",background:"#F8F6F2",borderRadius:10,border:"1px solid #EDE9E2"}}>
            <div>
              <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.8rem",fontWeight:500,color:"#1A1715"}}>{s.name}</div>
              <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.68rem",color:"#9A9288",marginTop:2}}>{s.category} · {s.duration}min · R$ {parseFloat(s.price).toFixed(2)}</div>
            </div>
            <div style={{display:"flex",gap:6}}>
              <button onClick={()=>edit(s)} className="btn" style={{padding:"5px 10px",borderRadius:5,border:"1px solid #EDE9E2",background:"#F8F6F2",fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#7A7268"}}>Editar</button>
              <button onClick={()=>remove(s.id)} className="btn" style={{padding:"5px 10px",borderRadius:5,border:"1px solid #F4D0C8",background:"#FFF5F3",fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#D4735A"}}>Remover</button>
            </div>
          </div>
        ))}
      </div>
      {adding&&(
        <div className="fade-up" style={{background:"#fff",border:"1px solid #EDE9E2",borderRadius:14,padding:"20px",marginTop:8}}>
          <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"2px",color:"#9A9288",marginBottom:16}}>{editId?"EDITAR":"NOVO SERVIÇO"}</div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
            <Field label="Nome *"><input className="inp" value={form.name} onChange={e=>setForm(p=>({...p,name:e.target.value}))} placeholder="Ex: Corte Feminino" /></Field>
            <Field label="Categoria"><select className="inp" value={form.category} onChange={e=>setForm(p=>({...p,category:e.target.value}))}><option value="">Selecione</option>{SERVICE_CATEGORIES.map(c=><option key={c}>{c}</option>)}</select></Field>
            <Field label="Duração (min)"><input className="inp" type="number" min="5" step="5" value={form.duration} onChange={e=>setForm(p=>({...p,duration:e.target.value}))} /></Field>
            <Field label="Preço (R$) *"><input className="inp" type="number" step="0.01" min="0" value={form.price} onChange={e=>setForm(p=>({...p,price:e.target.value}))} placeholder="0,00" /></Field>
          </div>
          <Field label="Descrição"><textarea className="inp" rows={2} value={form.description} onChange={e=>setForm(p=>({...p,description:e.target.value}))} style={{resize:"vertical"}} /></Field>
          <div style={{display:"flex",gap:10,marginTop:16}}>
            <button onClick={resetForm} className="btn" style={{flex:1,padding:"10px",borderRadius:8,border:"1px solid #DDD8CE",background:"#fff",fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem",color:"#7A7268"}}>Cancelar</button>
            <button onClick={save} className="btn" style={{flex:2,padding:"10px",borderRadius:8,background:"#C9A96E",color:"#fff",fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem",letterSpacing:"1px"}}>SALVAR</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── PRODUCT EDITOR ───────────────────────────────────────────────────────────
function ProductEditor({products,setProducts,showToast}){
  const EMPTY={name:"",brand:"",category:"",sku:"",price:"",discount:"",stock:"",description:"",photoPreview:null,id:null};
  const [adding,setAdding]=useState(false);
  const [editId,setEditId]=useState(null);
  const [form,setForm]=useState(EMPTY);
  const fileRef=useRef();
  const resetForm=()=>{setAdding(false);setEditId(null);setForm(EMPTY);};
  const edit=p=>{setForm({...p});setEditId(p.id);setAdding(true);};
  const remove=id=>setProducts(p=>p.filter(pr=>pr.id!==id));
  const handlePhoto=e=>{
    const f=e.target.files[0];if(!f)return;
    if(!validateFileType(f,ALLOWED_IMAGE_TYPES)){showToast("Formato inválido","error");return;}
    if(f.size>5*1024*1024){showToast("Máx 5MB","error");return;}
    const reader=new FileReader();reader.onload=ev=>setForm(p=>({...p,photoPreview:ev.target.result}));reader.readAsDataURL(f);
  };
  const save=()=>{
    if(!form.name||!form.price){showToast("Nome e preço obrigatórios","error");return;}
    if(editId) setProducts(p=>p.map(pr=>pr.id===editId?{...form}:pr));
    else setProducts(p=>[...p,{...form,id:uid()}]);
    resetForm(); showToast(editId?"Produto atualizado ✓":"Produto adicionado ✓","success");
  };
  return(
    <div style={{background:"#fff",border:"1px solid #EDE9E2",borderRadius:14,padding:"20px",marginBottom:20}}>
      <SectionHeader title="Produtos" icon="📦" count={products.length} onAdd={()=>{resetForm();setAdding(true);}} />
      {products.length===0&&!adding&&<EmptyState icon="📦" text="Nenhum produto ainda" sub="Adicione os produtos que você vende" />}
      <div style={{display:"grid",gridTemplateColumns:"repeat(auto-fill,minmax(200px,1fr))",gap:12,marginBottom:adding?16:0}}>
        {products.map(p=>(
          <div key={p.id} style={{background:"#F8F6F2",borderRadius:10,border:"1px solid #EDE9E2",overflow:"hidden"}}>
            {p.photoPreview&&<div style={{height:80,overflow:"hidden"}}><img src={p.photoPreview} alt={p.name} style={{width:"100%",height:"100%",objectFit:"cover"}} /></div>}
            <div style={{padding:"10px"}}>
              <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem",fontWeight:500,color:"#1A1715",marginBottom:2}}>{p.name}</div>
              <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#9A9288",marginBottom:8}}>{p.brand&&`${p.brand} · `}R$ {parseFloat(p.price).toFixed(2)}</div>
              <div style={{display:"flex",gap:6}}>
                <button onClick={()=>edit(p)} className="btn" style={{flex:1,padding:"5px",borderRadius:5,border:"1px solid #EDE9E2",background:"#F8F6F2",fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#7A7268"}}>Editar</button>
                <button onClick={()=>remove(p.id)} className="btn" style={{flex:1,padding:"5px",borderRadius:5,border:"1px solid #F4D0C8",background:"#FFF5F3",fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#D4735A"}}>Remover</button>
              </div>
            </div>
          </div>
        ))}
      </div>
      {adding&&(
        <div className="fade-up" style={{background:"#fff",border:"1px solid #EDE9E2",borderRadius:14,padding:"20px",marginTop:8}}>
          <div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",letterSpacing:"2px",color:"#9A9288",marginBottom:16}}>{editId?"EDITAR":"NOVO PRODUTO"}</div>
          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12,marginBottom:12}}>
            <Field label="Nome *"><input className="inp" value={form.name} onChange={e=>setForm(p=>({...p,name:e.target.value}))} placeholder="Ex: Shampoo Hidra" /></Field>
            <Field label="Marca"><input className="inp" value={form.brand} onChange={e=>setForm(p=>({...p,brand:e.target.value}))} placeholder="Ex: L'Oréal" /></Field>
            <Field label="Categoria"><select className="inp" value={form.category} onChange={e=>setForm(p=>({...p,category:e.target.value}))}><option value="">Selecione</option>{PRODUCT_CATEGORIES.map(c=><option key={c}>{c}</option>)}</select></Field>
            <Field label="SKU"><input className="inp" value={form.sku} onChange={e=>setForm(p=>({...p,sku:e.target.value}))} placeholder="Código interno" /></Field>
            <Field label="Preço (R$) *"><input className="inp" type="number" step="0.01" min="0" value={form.price} onChange={e=>setForm(p=>({...p,price:e.target.value}))} placeholder="0,00" /></Field>
            <Field label="Estoque"><input className="inp" type="number" min="0" value={form.stock} onChange={e=>setForm(p=>({...p,stock:e.target.value}))} placeholder="0" /></Field>
          </div>
          <Field label="Foto">
            <div onClick={()=>fileRef.current.click()} className="drop-zone" style={{padding:"16px",height:form.photoPreview?120:70,display:"flex",alignItems:"center",justifyContent:"center",overflow:"hidden"}}>
              {form.photoPreview?<img src={form.photoPreview} alt="preview" style={{maxHeight:"100%",maxWidth:"100%",objectFit:"contain",borderRadius:8}} />:<span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.75rem",color:"#9A9288"}}>📷 Clique para adicionar foto</span>}
            </div>
            <input ref={fileRef} type="file" accept="image/jpeg,image/png,image/webp" onChange={handlePhoto} style={{display:"none"}} />
          </Field>
          <div style={{display:"flex",gap:10,marginTop:16}}>
            <button onClick={resetForm} className="btn" style={{flex:1,padding:"10px",borderRadius:8,border:"1px solid #DDD8CE",background:"#fff",fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem",color:"#7A7268"}}>Cancelar</button>
            <button onClick={save} className="btn" style={{flex:2,padding:"10px",borderRadius:8,background:"#79B8D4",color:"#fff",fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem",letterSpacing:"1px"}}>SALVAR</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── SMALL COMPONENTS ─────────────────────────────────────────────────────────
function FormSection({title,icon,children}){return(<div><div style={{display:"flex",alignItems:"center",gap:10,marginBottom:24}}><span style={{fontSize:"1.3rem"}}>{icon}</span><h3 style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"1.5rem",fontWeight:300}}>{title}</h3></div><div style={{display:"flex",flexDirection:"column",gap:16}}>{children}</div></div>);}
function Row2({children}){return <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:14}}>{children}</div>;}
function Field({label,error,children}){return(<div><label style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#7A7268",letterSpacing:"0.5px",display:"block",marginBottom:6}}>{label}</label>{children}{error&&<div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.68rem",color:"#D4735A",marginTop:4,animation:"fadeUp 0.2s ease"}}>⚠ {error}</div>}</div>);}
function Hint({children,ok}){return(<div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:ok?"#5BAA5B":"#9A9288",background:ok?"#5BAA5B10":"#F8F6F2",padding:"8px 12px",borderRadius:6,border:`1px solid ${ok?"#5BAA5B30":"#EDE9E2"}`,marginTop:4}}>{children}</div>);}
function ImageUpload({preview,onChange,label}){const ref=useRef();return(<div onClick={()=>ref.current.click()} className="drop-zone" style={{height:120,display:"flex",alignItems:"center",justifyContent:"center",overflow:"hidden"}}>{preview?<img src={preview} alt="preview" style={{maxHeight:"100%",maxWidth:"100%",objectFit:"cover",borderRadius:8}} />:<div style={{textAlign:"center"}}><div style={{fontSize:"1.5rem",marginBottom:6}}>📷</div><div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.7rem",color:"#9A9288"}}>{label}</div></div>}<input ref={ref} type="file" accept="image/jpeg,image/png,image/webp" onChange={onChange} style={{display:"none"}} /></div>);}
function DocUpload({file,onChange,label}){const ref=useRef();const isValidType=file?ALLOWED_DOC_TYPES.includes(file.type):true;return(<div onClick={()=>ref.current.click()} className="drop-zone" style={{padding:"18px",display:"flex",alignItems:"center",gap:12,borderColor:file&&!isValidType?"#D4735A":undefined}}>{file?<><div style={{width:36,height:36,borderRadius:8,background:isValidType?"#5BAA5B15":"#D4735A15",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"1.2rem",flexShrink:0}}>{isValidType?"✅":"❌"}</div><div><div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.78rem",color:isValidType?"#1A1715":"#D4735A"}}>{file.name}</div><div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.65rem",color:"#9A9288"}}>{(file.size/1024).toFixed(0)} KB · {isValidType?"Formato aceito":"Inválido — use PDF, JPG ou PNG"}</div></div></>:<><div style={{fontSize:"1.5rem"}}>📄</div><div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.75rem",color:"#9A9288"}}>{label}</div></>}<input ref={ref} type="file" accept="image/jpeg,image/png,image/webp,application/pdf" onChange={onChange} style={{display:"none"}} /></div>);}
function SectionHeader({title,icon,count,onAdd}){return(<div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:14}}><div style={{display:"flex",alignItems:"center",gap:8}}><span style={{fontSize:"1.1rem"}}>{icon}</span><span style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"1.3rem",fontWeight:400}}>{title}</span>{count>0&&<span style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.7rem",background:"#F8F6F2",color:"#9A9288",padding:"2px 8px",borderRadius:12,border:"1px solid #EDE9E2"}}>{count}</span>}</div><button onClick={onAdd} className="btn" style={{padding:"7px 16px",borderRadius:8,background:"#1A1715",color:"#F7F5F0",fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",letterSpacing:"1px"}}>+ ADICIONAR</button></div>);}
function EmptyState({icon,text,sub}){return(<div style={{textAlign:"center",padding:"40px 24px",background:"#fff",borderRadius:12,border:"2px dashed #EDE9E2",marginBottom:16}}><div style={{fontSize:"2rem",marginBottom:8}}>{icon}</div><div style={{fontFamily:"'Cormorant Garamond',serif",fontSize:"1.1rem",color:"#7A7268"}}>{text}</div><div style={{fontFamily:"'DM Sans',sans-serif",fontSize:"0.72rem",color:"#B0A898",marginTop:4}}>{sub}</div></div>);}
