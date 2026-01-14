
import React, { useState, useEffect } from 'react';
import { 
  Shield, Key, Globe, Lock, Save, Loader2, CheckCircle2, Copy, 
  Terminal, Eye, EyeOff, RefreshCw, Code, BookOpen, AlertTriangle,
  Server, ExternalLink, Plus, X, Link, CloudLightning, FileText, Info, Trash2,
  Archive, Download, Upload, HardDrive, FileJson, Database
} from 'lucide-react';

const ProjectSettings: React.FC<{ projectId: string }> = ({ projectId }) => {
  const [project, setProject] = useState<any>(null);
  const [customDomain, setCustomDomain] = useState('');
  const [availableCerts, setAvailableCerts] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Database Config State
  const [dbConfig, setDbConfig] = useState<{ max_connections: number, idle_timeout_seconds: number, statement_timeout_ms: number }>({
      max_connections: 10,
      idle_timeout_seconds: 60,
      statement_timeout_ms: 15000 // Default 15s
  });

  // Security State
  const [revealedKeyValues, setRevealedKeyValues] = useState<Record<string, string>>({});

  // Origins State
  const [origins, setOrigins] = useState<any[]>([]);
  const [newOrigin, setNewOrigin] = useState('');

  // Verification Modal State
  const [showVerifyModal, setShowVerifyModal] = useState(false);
  const [verifyPassword, setVerifyPassword] = useState('');
  
  type SecurityIntent = 
    | { type: 'REVEAL_KEY', keyType: string }
    | { type: 'ROTATE_KEY', keyType: string }
    | { type: 'DELETE_DOMAIN' };

  const [pendingIntent, setPendingIntent] = useState<SecurityIntent | null>(null);
  const [verifyLoading, setVerifyLoading] = useState(false);

  // Backup State
  const [exporting, setExporting] = useState(false);

  // --- UI LOGIC ---
  const isInputDirty = customDomain !== (project?.custom_domain || '');
  
  const bestCertMatch = availableCerts.find(cert => {
      if (cert === customDomain) return true;
      if (cert.startsWith('*.')) {
          const root = cert.slice(2);
          if (customDomain.endsWith(root)) {
              const domainParts = customDomain.split('.');
              const rootParts = root.split('.');
              return domainParts.length === rootParts.length + 1;
          }
      }
      return false;
  });

  const copyToClipboard = (text: string) => {
    if (!text) return;
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text)
            .then(() => { setSuccess("Copiado!"); setTimeout(() => setSuccess(null), 2000); })
            .catch(() => alert("Erro ao copiar (HTTPS)."));
        return;
    }
    try {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        textArea.style.left = "-9999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        setSuccess("Copiado!");
        setTimeout(() => setSuccess(null), 2000);
    } catch (err) { alert("Erro ao copiar."); }
  };

  const fetchProject = async () => {
    try {
        const res = await fetch('/api/control/projects', {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` }
        });
        const data = await res.json();
        const current = data.find((p: any) => p.slug === projectId);
        
        if (current) {
            setProject(current);
            setCustomDomain(current.custom_domain || '');
            
            const rawOrigins = current.metadata?.allowed_origins || [];
            setOrigins(rawOrigins.map((o: any) => typeof o === 'string' ? { url: o, require_auth: true } : o));

            if (current.metadata?.db_config) {
                setDbConfig({
                    max_connections: current.metadata.db_config.max_connections || 10,
                    idle_timeout_seconds: current.metadata.db_config.idle_timeout_seconds || 60,
                    statement_timeout_ms: current.metadata.db_config.statement_timeout_ms || 15000
                });
            }
        }
        
        fetchAvailableCerts();
    } catch (e) {
        console.error("Failed to sync project settings");
    } finally {
        setLoading(false);
    }
  };

  const fetchAvailableCerts = async () => {
    try {
        const certRes = await fetch('/api/control/system/certificates/status', {
            headers: { 'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` }
        });
        const certData = await certRes.json();
        setAvailableCerts(certData.domains || []);
    } catch(e) { console.error("Cert list failed"); }
  };

  useEffect(() => { fetchProject(); }, [projectId]);

  // --- ACTIONS ---

  const handleVerifyAndExecute = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!verifyPassword) { alert("Digite a senha."); return; }
    if (!pendingIntent) return;

    setVerifyLoading(true);
    
    if (pendingIntent.type === 'REVEAL_KEY') {
        try {
            const keyType = pendingIntent.keyType === 'service' ? 'service_key' : pendingIntent.keyType === 'anon' ? 'anon_key' : 'jwt_secret';
            const res = await fetch(`/api/control/projects/${projectId}/reveal-key`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` },
                body: JSON.stringify({ password: verifyPassword, keyType: keyType })
            });
            const data = await res.json();
            if (!res.ok) { alert(data.error || "Senha incorreta."); } else {
                setRevealedKeyValues(prev => ({ ...prev, [pendingIntent.keyType]: data.key }));
                setTimeout(() => { setRevealedKeyValues(prev => { const updated = { ...prev }; delete updated[pendingIntent.keyType]; return updated; }); }, 60000);
                setShowVerifyModal(false); setVerifyPassword('');
            }
        } catch (e: any) { alert("Erro de conexão."); } finally { setVerifyLoading(false); setPendingIntent(null); }
        return;
    }

    try {
        const verifyRes = await fetch('/api/control/auth/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` },
            body: JSON.stringify({ password: verifyPassword })
        });

        if (!verifyRes.ok) { alert("Senha incorreta."); setVerifyLoading(false); return; }

        setShowVerifyModal(false); 
        setVerifyPassword('');

        if (pendingIntent.type === 'ROTATE_KEY') await executeRotateKey(pendingIntent.keyType);
        else if (pendingIntent.type === 'DELETE_DOMAIN') await executeDeleteDomain();

    } catch (e) { alert("Erro no processo de verificação."); } 
    finally { 
        setVerifyLoading(false); 
        setPendingIntent(null); 
    }
  };

  const executeRotateKey = async (type: string) => {
    setRotating(type);
    try {
      await fetch(`/api/control/projects/${projectId}/rotate-keys`, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` }, body: JSON.stringify({ type }) });
      await fetchProject();
      setSuccess(`${type.toUpperCase()} rotacionada.`);
      const next = { ...revealedKeyValues }; delete next[type.replace('_key', '').replace('_secret', '')]; setRevealedKeyValues(next);
      setTimeout(() => setSuccess(null), 3000);
    } catch (e) { alert('Falha ao rotacionar chave.'); } finally { setRotating(null); }
  };

  const executeDeleteDomain = async () => {
      setSaving(true);
      try {
          const res = await fetch(`/api/control/projects/${projectId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` },
            body: JSON.stringify({ custom_domain: null })
          });
          
          if (res.ok) {
              setSuccess('Domínio desvinculado.');
              setProject((prev: any) => ({ ...prev, custom_domain: null }));
              setCustomDomain('');
              setTimeout(() => { fetchProject(); setSuccess(null); }, 1500);
          }
      } catch(e) { 
          alert('Erro ao remover domínio.'); 
      } finally { 
          setSaving(false); 
      }
  };

  const handleUpdateSettings = async (overrideOrigins?: any[]) => {
    setSaving(true);
    try {
      const payload: any = { custom_domain: customDomain };
      
      const metaUpdate: any = { db_config: dbConfig };
      if (overrideOrigins) metaUpdate.allowed_origins = overrideOrigins;
      
      // Need to merge with existing metadata properly in backend, but here we just send what changed
      payload.metadata = metaUpdate;

      const res = await fetch(`/api/control/projects/${projectId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` },
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        setSuccess('Configuração salva.');
        if (!overrideOrigins) fetchProject(); 
        setTimeout(() => setSuccess(null), 3000);
      }
    } catch (e) { alert('Erro ao salvar.'); } finally { setSaving(false); }
  };

  const toggleSchemaExposure = async () => {
      if (!project) return;
      setSaving(true);
      try {
          const current = project.metadata?.schema_exposure || false;
          const newMetadata = { ...project.metadata, schema_exposure: !current };
          
          const res = await fetch(`/api/control/projects/${projectId}`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` },
              body: JSON.stringify({ metadata: newMetadata })
          });

          if (res.ok) {
              setProject({ ...project, metadata: newMetadata });
              setSuccess(!current ? "Discovery Enabled (Public Swagger)" : "Discovery Disabled (Secure Mode)");
              setTimeout(() => setSuccess(null), 2000);
          }
      } catch (e) {
          alert("Falha ao atualizar.");
      } finally {
          setSaving(false);
      }
  };

  const addOrigin = () => {
    if (!newOrigin) return;
    try { new URL(newOrigin); } catch { alert('URL inválida.'); return; }
    const updated = [...origins, { url: newOrigin, require_auth: true }];
    setOrigins(updated); setNewOrigin(''); handleUpdateSettings(updated);
  };

  const removeOrigin = (url: string) => {
    const updated = origins.filter(o => o.url !== url);
    setOrigins(updated); handleUpdateSettings(updated);
  };

  const handleDownloadBackup = async () => {
      setExporting(true);
      try {
          const res = await fetch(`/api/control/projects/${projectId}/export`, { headers: { 'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` } });
          if (!res.ok) throw new Error("Download failed");
          const blob = await res.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a'); a.href = url; a.download = `${project.slug}_backup.caf`; document.body.appendChild(a); a.click(); window.URL.revokeObjectURL(url); document.body.removeChild(a);
      } catch (e) { alert("Erro ao baixar backup."); } finally { setExporting(false); }
  };

  // --- UI HANDLERS ---
  const handleRevealClick = (keyType: string) => {
      if (revealedKeyValues[keyType]) {
          const next = { ...revealedKeyValues }; delete next[keyType]; setRevealedKeyValues(next); return;
      }
      setPendingIntent({ type: 'REVEAL_KEY', keyType }); setShowVerifyModal(true);
  };
  const handleRotateClick = (keyType: string) => { setPendingIntent({ type: 'ROTATE_KEY', keyType }); setShowVerifyModal(true); };
  
  const handleSaveDomainClick = () => {
      if (!customDomain) { alert("Digite um domínio."); return; }
      handleUpdateSettings();
  };

  const handleDeleteDomainClick = () => {
      setPendingIntent({ type: 'DELETE_DOMAIN' });
      setShowVerifyModal(true);
  };

  if (loading) return <div className="p-20 flex justify-center"><Loader2 className="animate-spin text-indigo-600" /></div>;

  const apiEndpoint = project?.custom_domain ? `https://${project.custom_domain}` : `${window.location.origin}/api/data/${project?.slug}`;
  const sdkCode = `import { createClient } from './lib/cascata-sdk';\nconst cascata = createClient('${apiEndpoint}', '${project?.anon_key || 'anon_key'}');`;

  return (
    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 space-y-12 pb-40">
      {success && <div className="fixed top-8 left-1/2 -translate-x-1/2 z-[500] p-5 rounded-3xl bg-indigo-600 text-white shadow-2xl flex items-center gap-4 animate-bounce"><CheckCircle2 size={20} /><span className="text-sm font-black uppercase tracking-tight">{success}</span></div>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
        
        {/* DATA SOVEREIGNTY */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-[3.5rem] p-12 shadow-2xl relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-16 opacity-5 group-hover:scale-110 transition-transform duration-700"><Archive size={200} className="text-white" /></div>
            <div className="relative z-10 flex flex-col md:flex-row items-start md:items-center justify-between gap-8">
                <div><h3 className="text-3xl font-black text-white tracking-tight flex items-center gap-4 mb-2"><div className="w-14 h-14 bg-indigo-600 text-white rounded-2xl flex items-center justify-center shadow-lg"><HardDrive size={24} /></div>Data Sovereignty</h3><p className="text-slate-400 font-medium max-w-xl text-sm leading-relaxed">Full ownership of your infrastructure. Generate a cryptographic snapshot (CAF).</p></div>
                <button onClick={handleDownloadBackup} disabled={exporting} className="bg-white text-slate-900 px-8 py-4 rounded-3xl font-black text-xs uppercase tracking-widest hover:bg-indigo-50 transition-all flex items-center gap-3 shadow-xl active:scale-95 disabled:opacity-70">{exporting ? <Loader2 size={18} className="animate-spin text-indigo-600"/> : <Download size={18} className="text-indigo-600" />}Download Snapshot (.caf)</button>
            </div>
        </div>

        {/* DOMAIN & SSL */}
        <div className="bg-white border border-slate-200 rounded-[3.5rem] p-12 shadow-sm space-y-10">
           <div className="flex items-center justify-between">
              <h3 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-4">
                <div className="w-12 h-12 bg-indigo-600 text-white rounded-2xl flex items-center justify-center shadow-lg"><Globe size={20} /></div>
                Endpoint Público
              </h3>
           </div>
           
           <div className="space-y-6">
              <div className="space-y-2">
                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Custom API Domain</label>
                <div className="flex gap-2">
                    <input 
                        value={customDomain} 
                        onChange={(e) => setCustomDomain(e.target.value)} 
                        placeholder="api.meu-app.com"
                        className="flex-1 bg-slate-50 border border-slate-100 rounded-2xl py-4 px-6 text-sm font-bold text-slate-900 outline-none focus:ring-4 focus:ring-indigo-500/10 transition-all disabled:bg-slate-100 disabled:text-slate-500" 
                    />
                    {(isInputDirty || !project?.custom_domain) && (
                        <button onClick={handleSaveDomainClick} disabled={saving || !customDomain} className="bg-indigo-600 text-white px-6 rounded-2xl font-black text-xs uppercase tracking-widest hover:bg-indigo-700 transition-all shadow-lg flex items-center gap-2">{saving ? <Loader2 size={14} className="animate-spin"/> : <Save size={14} />} Salvar</button>
                    )}
                    {project?.custom_domain && !isInputDirty && (
                        <button onClick={handleDeleteDomainClick} className="bg-rose-50 text-rose-600 p-4 rounded-2xl hover:bg-rose-600 hover:text-white transition-all shadow-sm" title="Desvincular Domínio"><Trash2 size={18} /></button>
                    )}
                </div>
              </div>
              {customDomain && (
                  <div className={`p-6 rounded-2xl border flex items-center justify-between transition-colors ${bestCertMatch ? 'bg-emerald-50 border-emerald-100' : 'bg-amber-50 border-amber-100'}`}>
                      <div className="flex items-center gap-4">
                          <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${bestCertMatch ? 'bg-emerald-500 text-white' : 'bg-amber-500 text-white'}`}>
                              {bestCertMatch ? <CheckCircle2 size={20}/> : <AlertTriangle size={20}/>}
                          </div>
                          <div>
                              <h4 className={`font-bold text-sm ${bestCertMatch ? 'text-emerald-900' : 'text-amber-900'}`}>{bestCertMatch ? 'Conexão Segura (SSL Detectado)' : 'Certificado Ausente'}</h4>
                              <p className={`text-xs ${bestCertMatch ? 'text-emerald-700' : 'text-amber-700'}`}>{bestCertMatch ? `Coberto pelo certificado do cofre: ${bestCertMatch}` : `Adicione um certificado para ${customDomain} (ou wildcard) no System Settings.`}</p>
                          </div>
                      </div>
                      {!bestCertMatch && (<button onClick={() => window.location.hash = '#/settings'} className="bg-white px-4 py-2 rounded-xl text-xs font-bold text-amber-700 shadow-sm hover:bg-amber-50 transition-colors">Ir para Cofre</button>)}
                  </div>
              )}
           </div>
        </div>

        {/* Global Origins */}
        <div className="bg-white border border-slate-200 rounded-[3.5rem] p-12 shadow-sm space-y-10">
           <h3 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-4"><div className="w-12 h-12 bg-emerald-600 text-white rounded-2xl flex items-center justify-center shadow-lg"><Link size={20} /></div>Global Allowed Origins</h3>
           <div className="space-y-6">
              <div className="flex gap-4">
                 <input value={newOrigin} onChange={(e) => setNewOrigin(e.target.value)} placeholder="https://meu-app.com" className="flex-1 bg-slate-50 border border-slate-100 rounded-2xl py-3 px-6 text-sm font-bold outline-none focus:ring-4 focus:ring-emerald-500/10" />
                 <button onClick={addOrigin} className="bg-emerald-600 text-white px-4 rounded-2xl hover:bg-emerald-700 transition-all"><Plus size={20} /></button>
              </div>
              <div className="space-y-3 max-h-60 overflow-y-auto pr-2 custom-scrollbar">
                 {origins.map((origin, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-slate-50 p-4 rounded-2xl border border-slate-100"><span className="text-xs font-bold text-slate-700">{origin.url}</span><button onClick={() => removeOrigin(origin.url)} className="text-slate-300 hover:text-rose-600"><X size={16} /></button></div>
                 ))}
              </div>
           </div>
        </div>

        {/* DATABASE TUNING (NEW CARD) */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-[3.5rem] p-12 shadow-sm flex flex-col md:flex-row items-center justify-between gap-8">
            <div className="flex items-center gap-6">
                <div className="w-14 h-14 bg-blue-50 text-blue-600 rounded-2xl flex items-center justify-center shadow-inner">
                    <Database size={28} />
                </div>
                <div>
                    <h3 className="text-2xl font-black text-slate-900 tracking-tight">Database Tuning</h3>
                    <p className="text-slate-400 font-medium mt-1 text-sm max-w-xl">
                        Optimize the connection pool for this specific tenant.
                    </p>
                </div>
            </div>

            <div className="flex gap-4 items-end">
                <div>
                    <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest ml-1">Max Connections</label>
                    <input 
                        type="number" 
                        min="1"
                        max="100"
                        value={dbConfig.max_connections}
                        onChange={(e) => setDbConfig({...dbConfig, max_connections: parseInt(e.target.value)})}
                        className="w-24 bg-slate-50 border border-slate-100 rounded-2xl py-3 px-4 text-sm font-bold text-center outline-none" 
                    />
                </div>
                <div>
                    <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest ml-1">Idle (s)</label>
                    <input 
                        type="number"
                        min="10"
                        value={dbConfig.idle_timeout_seconds}
                        onChange={(e) => setDbConfig({...dbConfig, idle_timeout_seconds: parseInt(e.target.value)})}
                        className="w-24 bg-slate-50 border border-slate-100 rounded-2xl py-3 px-4 text-sm font-bold text-center outline-none" 
                    />
                </div>
                <div>
                    <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest ml-1">Max Query (ms)</label>
                    <input 
                        type="number"
                        min="1000"
                        step="1000"
                        value={dbConfig.statement_timeout_ms}
                        onChange={(e) => setDbConfig({...dbConfig, statement_timeout_ms: parseInt(e.target.value)})}
                        className="w-28 bg-slate-50 border border-slate-100 rounded-2xl py-3 px-4 text-sm font-bold text-center outline-none" 
                        title="Statement Timeout"
                    />
                </div>
                <button onClick={() => handleUpdateSettings()} disabled={saving} className="bg-blue-600 text-white px-6 py-3 rounded-2xl font-black text-xs uppercase tracking-widest hover:bg-blue-700 transition-all shadow-lg flex items-center gap-2 h-[46px]">
                    {saving ? <Loader2 size={14} className="animate-spin"/> : 'Apply'}
                </button>
            </div>
        </div>

        {/* API SCHEMA DISCOVERY (NEW CARD) */}
        <div className="lg:col-span-2 bg-white border border-slate-200 rounded-[3.5rem] p-12 shadow-sm flex flex-col md:flex-row items-center justify-between gap-8">
            <div className="flex items-center gap-6">
                <div className="w-14 h-14 bg-amber-50 text-amber-600 rounded-2xl flex items-center justify-center shadow-inner">
                    <FileJson size={28} />
                </div>
                <div>
                    <h3 className="text-2xl font-black text-slate-900 tracking-tight">API Schema Discovery</h3>
                    <p className="text-slate-400 font-medium mt-1 text-sm max-w-xl">
                        Allows external tools (FlutterFlow, AppSmith, Postman) to inspect your database structure via OpenAPI/Swagger.
                    </p>
                    <div className="flex items-center gap-2 mt-3">
                        <span className="text-[10px] font-bold bg-amber-50 text-amber-700 px-2 py-1 rounded uppercase tracking-widest border border-amber-100">Security Recommendation</span>
                        <span className="text-[10px] font-bold text-slate-400">Enable only during setup, then disable.</span>
                    </div>
                </div>
            </div>

            <button
                onClick={toggleSchemaExposure}
                disabled={saving}
                className={`w-20 h-10 rounded-full p-1 transition-all duration-300 shadow-inner ${project?.metadata?.schema_exposure ? 'bg-emerald-500' : 'bg-slate-200'}`}
                title={project?.metadata?.schema_exposure ? "Schema Exposed (Public)" : "Schema Hidden (Secure)"}
            >
                <div className={`w-8 h-8 bg-white rounded-full shadow-md transition-all duration-300 transform ${project?.metadata?.schema_exposure ? 'translate-x-10' : 'translate-x-0'}`}></div>
            </button>
        </div>

        {/* Keys & SDK */}
        <div className="bg-white border border-slate-200 rounded-[3.5rem] p-12 shadow-sm space-y-10">
           <div className="space-y-2">
               <h3 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-4"><div className="w-12 h-12 bg-slate-900 text-white rounded-2xl flex items-center justify-center shadow-lg"><Lock size={20} /></div>Gerenciamento de Segredos</h3>
           </div>
           <div className="space-y-8">
              <KeyControl 
                label="Anon Key" 
                value={project?.anon_key || '******'} 
                isSecret={false} 
                isRevealed={true} 
                onToggleReveal={() => {}} 
                onRotate={() => handleRotateClick('anon')} 
                loading={rotating === 'anon'} 
                copyFn={copyToClipboard} 
              />
              <KeyControl 
                label="Service Key" 
                value={revealedKeyValues['service'] || project?.service_key || '******'} 
                isSecret={true} 
                isRevealed={!!revealedKeyValues['service']} 
                onToggleReveal={() => handleRevealClick('service')} 
                onRotate={() => handleRotateClick('service')} 
                loading={rotating === 'service'} 
                copyFn={copyToClipboard} 
              />
              <KeyControl 
                label="JWT Secret" 
                value={revealedKeyValues['jwt'] || project?.jwt_secret || '******'} 
                isSecret={true} 
                isRevealed={!!revealedKeyValues['jwt']} 
                onToggleReveal={() => handleRevealClick('jwt')} 
                onRotate={() => handleRotateClick('jwt')} 
                loading={rotating === 'jwt'} 
                copyFn={copyToClipboard} 
              />
           </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-[3.5rem] p-12 shadow-sm space-y-8">
           <h3 className="text-2xl font-black text-white tracking-tight flex items-center gap-4"><div className="w-12 h-12 bg-indigo-600 text-white rounded-2xl flex items-center justify-center"><Code size={20} /></div>Cascata SDK</h3>
           <div className="relative group"><pre className="bg-slate-950 p-8 rounded-[2rem] text-[11px] font-mono text-emerald-400 overflow-x-auto leading-relaxed border border-white/5">{sdkCode}</pre><button onClick={() => copyToClipboard(sdkCode)} className="absolute top-4 right-4 p-3 bg-white/5 hover:bg-white/10 text-white rounded-xl transition-all"><Copy size={16} /></button></div>
        </div>
      </div>

      {/* Verify Password Modal */}
      {showVerifyModal && (
         <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-[800] flex items-center justify-center p-8 animate-in zoom-in-95">
            <div className="bg-white rounded-[3rem] p-10 max-w-sm w-full shadow-2xl text-center border border-slate-200">
               <Lock size={40} className="mx-auto text-slate-900 mb-6" />
               <h3 className="text-xl font-black text-slate-900 mb-2">Confirmação de Segurança</h3>
               <p className="text-xs text-slate-500 font-bold mb-8">Digite sua senha mestra para autorizar.</p>
               <form onSubmit={handleVerifyAndExecute}><input type="password" autoFocus value={verifyPassword} onChange={e => setVerifyPassword(e.target.value)} className="w-full bg-slate-50 border border-slate-200 rounded-2xl py-4 px-6 text-center font-bold text-slate-900 outline-none mb-6 focus:ring-4 focus:ring-indigo-500/10" placeholder="••••••••"/><button type="submit" disabled={verifyLoading} className="w-full bg-slate-900 text-white py-4 rounded-2xl font-black text-xs uppercase tracking-widest shadow-xl hover:bg-indigo-600 transition-all flex items-center justify-center">{verifyLoading ? <Loader2 className="animate-spin"/> : 'Confirmar Acesso'}</button></form>
               <button onClick={() => { setShowVerifyModal(false); setPendingIntent(null); }} className="mt-4 text-xs font-bold text-slate-400 hover:text-slate-600">Cancelar</button>
            </div>
         </div>
      )}
    </div>
  );
};

const KeyControl = ({ label, value, isSecret, isRevealed, onToggleReveal, onRotate, loading, copyFn }: any) => {
  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center px-1"><label className="text-[10px] font-black text-slate-400 uppercase tracking-widest">{label}</label><div className="flex gap-4">{isSecret && (<button onClick={onToggleReveal} className="text-[10px] font-black text-indigo-600 uppercase hover:underline flex items-center gap-1">{isRevealed ? <><EyeOff size={10}/> Ocultar</> : <><Eye size={10}/> Revelar (Sudo)</>}</button>)}<button onClick={onRotate} disabled={loading} className="text-[10px] font-black text-rose-600 uppercase hover:underline flex items-center gap-1">{loading ? <Loader2 size={10} className="animate-spin" /> : <RefreshCw size={10} />} Rotacionar</button></div></div>
      <div className="relative group"><input type={isSecret && !isRevealed ? 'password' : 'text'} value={value || ''} readOnly className="w-full bg-slate-50 border border-slate-100 rounded-2xl py-4 pl-6 pr-14 text-[12px] font-mono font-bold text-slate-700 outline-none" /><button onClick={() => { if (isSecret && !isRevealed) { alert("Desbloqueie a chave primeiro para copiar."); } else { copyFn(value); }}} className="absolute right-4 top-1/2 -translate-y-1/2 text-slate-300 hover:text-indigo-600 p-2"><Copy size={16} /></button></div>
    </div>
  );
};

export default ProjectSettings;
