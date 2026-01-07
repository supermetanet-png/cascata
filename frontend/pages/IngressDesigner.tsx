
import React, { useState, useEffect } from 'react';
import { 
  ArrowLeft, Save, ShieldCheck, Play, Plus, Trash2, 
  Settings, Database, Zap, GitBranch, Terminal, Loader2,
  CheckCircle2, AlertCircle, Copy, Box, Lock, Variable
} from 'lucide-react';

interface IngressDesignerProps {
  projectId: string;
  hookId: string; // 'new' or UUID
  onBack: () => void;
}

// Logic Blocks Definition
interface IngressBlock {
    id: string;
    type: 'condition' | 'action_db' | 'action_rpc';
    config: any;
    // UI Helpers
    field?: string; // Condition
    operator?: string; // Condition
    value?: string; // Condition
    
    table?: string; // DB
    operation?: 'INSERT' | 'UPDATE' | 'DELETE'; // DB
    data?: Record<string, any>; // DB Mappings
    match_field?: string; // DB
    match_value?: string; // DB

    rpc_name?: string; // RPC
    rpc_args?: Record<string, any>; // RPC
    
    true_steps?: IngressBlock[]; // Recursive for Condition
}

const IngressDesigner: React.FC<IngressDesignerProps> = ({ projectId, hookId, onBack }) => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState<'config' | 'flow'>('config');
  
  // Basic Config
  const [name, setName] = useState('');
  const [routeSlug, setRouteSlug] = useState('');
  const [isActive, setIsActive] = useState(true);
  
  // Security Config
  const [securityConfig, setSecurityConfig] = useState({
      verify_signature: false,
      header_key: 'x-signature',
      secret: '',
      algorithm: 'sha256',
      allowed_ips: [] as string[],
      idempotency_key: ''
  });

  // Flow Definition (The Logic Tree)
  const [flow, setFlow] = useState<IngressBlock[]>([]);

  // Metadata for Selects
  const [tables, setTables] = useState<string[]>([]);
  const [rpcs, setRpcs] = useState<string[]>([]);
  
  // Toast
  const [notification, setNotification] = useState<{ type: 'success' | 'error', msg: string } | null>(null);

  // Init
  useEffect(() => {
      const init = async () => {
          try {
              const token = localStorage.getItem('cascata_token');
              const headers = { 'Authorization': `Bearer ${token}` };

              // Load Metadata
              const [tblRes, rpcRes] = await Promise.all([
                  fetch(`/api/data/${projectId}/tables`, { headers }),
                  fetch(`/api/data/${projectId}/functions`, { headers })
              ]);
              const tblData = await tblRes.json();
              const rpcData = await rpcRes.json();
              setTables(tblData.map((t: any) => t.name));
              setRpcs(rpcData.map((r: any) => r.name));

              if (hookId !== 'new') {
                  // Load Existing Hook
                  const hooksRes = await fetch(`/api/data/${projectId}/hooks/in`, { headers });
                  const hooks = await hooksRes.json();
                  const current = hooks.find((h: any) => h.id === hookId);
                  if (current) {
                      setName(current.name);
                      setRouteSlug(current.route_slug);
                      setIsActive(current.is_active);
                      setSecurityConfig({ ...securityConfig, ...current.security_config });
                      setFlow(current.flow_definition || []);
                  }
              } else {
                  // New Hook Defaults
                  setRouteSlug(`hook-${Date.now().toString(36)}`);
              }
          } catch(e) {
              setNotification({ type: 'error', msg: "Failed to load data" });
          } finally {
              setLoading(false);
          }
      };
      init();
  }, [projectId, hookId]);

  const handleSave = async () => {
      if (!name || !routeSlug) {
          setNotification({ type: 'error', msg: "Name and Slug are required." });
          return;
      }
      setSaving(true);
      try {
          const token = localStorage.getItem('cascata_token');
          const payload = {
              name,
              route_slug: routeSlug,
              is_active: isActive,
              security_config: securityConfig,
              flow_definition: flow
          };

          let res;
          if (hookId === 'new') {
              res = await fetch(`/api/data/${projectId}/hooks/in`, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                  body: JSON.stringify(payload)
              });
          } else {
              res = await fetch(`/api/data/${projectId}/hooks/in/${hookId}`, {
                  method: 'PATCH',
                  headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                  body: JSON.stringify(payload)
              });
          }

          if (res.ok) {
              setNotification({ type: 'success', msg: "Endpoint saved successfully." });
              if (hookId === 'new') onBack(); 
          } else {
              throw new Error("Failed to save");
          }
      } catch(e) {
          setNotification({ type: 'error', msg: "Error saving endpoint." });
      } finally {
          setSaving(false);
          setTimeout(() => setNotification(null), 3000);
      }
  };

  const addBlock = (type: IngressBlock['type']) => {
      const newBlock: IngressBlock = {
          id: crypto.randomUUID(),
          type,
          config: {},
          // Defaults based on type
          ...(type === 'condition' ? { field: 'body.status', operator: 'eq', value: 'paid', true_steps: [] } : {}),
          ...(type === 'action_db' ? { table: tables[0] || 'users', operation: 'INSERT', data: {} } : {}),
          ...(type === 'action_rpc' ? { rpc_name: rpcs[0] || '', rpc_args: {} } : {})
      };
      setFlow(prev => [...prev, newBlock]);
  };

  const removeBlock = (id: string) => {
      setFlow(prev => prev.filter(b => b.id !== id));
  };

  const updateBlock = (id: string, updates: Partial<IngressBlock>) => {
      setFlow(prev => prev.map(b => b.id === id ? { ...b, ...updates, config: { ...b.config, ...updates } } : b));
  };

  if (loading) return <div className="h-screen flex items-center justify-center"><Loader2 className="animate-spin text-indigo-600" size={40}/></div>;

  return (
    <div className="flex flex-col h-screen bg-[#F0F4F8] relative z-50">
        
        {/* TOAST */}
        {notification && (
            <div className={`fixed top-8 left-1/2 -translate-x-1/2 z-[100] px-6 py-3 rounded-full shadow-xl flex items-center gap-3 animate-in slide-in-from-top-4 ${notification.type === 'error' ? 'bg-rose-600 text-white' : 'bg-emerald-600 text-white'}`}>
                {notification.type === 'error' ? <AlertCircle size={18}/> : <CheckCircle2 size={18}/>}
                <span className="text-xs font-bold">{notification.msg}</span>
            </div>
        )}

        {/* HEADER */}
        <header className="h-20 bg-white border-b border-slate-200 flex items-center justify-between px-8 shrink-0">
            <div className="flex items-center gap-6">
                <button onClick={onBack} className="p-2 hover:bg-slate-100 rounded-full transition-colors text-slate-400 hover:text-slate-900">
                    <ArrowLeft size={24} />
                </button>
                <div>
                    <h1 className="text-2xl font-black text-slate-900 tracking-tight flex items-center gap-3">
                        Ingress Designer <span className="bg-indigo-100 text-indigo-700 px-2 py-0.5 rounded text-[10px] uppercase tracking-widest font-bold border border-indigo-200">Beta</span>
                    </h1>
                    <p className="text-[10px] text-slate-400 font-bold uppercase tracking-widest mt-1">
                        Webhooks & External Events
                    </p>
                </div>
            </div>

            <div className="flex items-center gap-4">
                <div className="flex bg-slate-100 p-1.5 rounded-xl">
                    <button onClick={() => setActiveTab('config')} className={`px-4 py-2 rounded-lg text-xs font-black uppercase tracking-widest transition-all flex items-center gap-2 ${activeTab === 'config' ? 'bg-white shadow text-indigo-600' : 'text-slate-400 hover:text-slate-600'}`}>
                        <Settings size={14}/> Config & Security
                    </button>
                    <button onClick={() => setActiveTab('flow')} className={`px-4 py-2 rounded-lg text-xs font-black uppercase tracking-widest transition-all flex items-center gap-2 ${activeTab === 'flow' ? 'bg-white shadow text-indigo-600' : 'text-slate-400 hover:text-slate-600'}`}>
                        <GitBranch size={14}/> Logic Flow
                    </button>
                </div>
                <button 
                    onClick={handleSave} 
                    disabled={saving}
                    className="bg-slate-900 text-white px-6 py-3 rounded-xl font-black text-xs uppercase tracking-widest hover:bg-indigo-600 transition-all flex items-center gap-2 shadow-xl disabled:opacity-50"
                >
                    {saving ? <Loader2 size={16} className="animate-spin"/> : <Save size={16}/>} Save Endpoint
                </button>
            </div>
        </header>

        {/* MAIN CONTENT */}
        <main className="flex-1 overflow-hidden relative">
            
            {/* TAB: CONFIG */}
            {activeTab === 'config' && (
                <div className="h-full overflow-y-auto p-12 max-w-4xl mx-auto space-y-10">
                    <div className="bg-white rounded-[2rem] p-8 shadow-sm border border-slate-200">
                        <h3 className="text-xl font-black text-slate-900 mb-6 flex items-center gap-3"><Settings className="text-indigo-500"/> General Settings</h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="space-y-2">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Name</label>
                                <input value={name} onChange={e => setName(e.target.value)} className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm font-bold outline-none focus:ring-2 focus:ring-indigo-500/20" placeholder="Stripe Payment Success"/>
                            </div>
                            <div className="space-y-2">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Route Slug</label>
                                <div className="flex items-center">
                                    <span className="bg-slate-100 text-slate-400 text-xs font-mono px-3 py-3 rounded-l-xl border-y border-l border-slate-200">.../hooks/in/</span>
                                    <input value={routeSlug} onChange={e => setRouteSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-_]/g, ''))} className="flex-1 bg-white border border-slate-200 rounded-r-xl px-4 py-3 text-sm font-bold outline-none focus:ring-2 focus:ring-indigo-500/20"/>
                                </div>
                            </div>
                            <div className="col-span-2 flex items-center gap-4 bg-slate-50 p-4 rounded-xl border border-slate-100">
                                <label className="text-xs font-bold text-slate-700">Endpoint Active</label>
                                <button onClick={() => setIsActive(!isActive)} className={`w-12 h-6 rounded-full p-1 transition-colors ${isActive ? 'bg-emerald-500' : 'bg-slate-300'}`}>
                                    <div className={`w-4 h-4 bg-white rounded-full shadow-md transition-transform ${isActive ? 'translate-x-6' : ''}`}></div>
                                </button>
                            </div>
                        </div>
                    </div>

                    <div className="bg-white rounded-[2rem] p-8 shadow-sm border border-slate-200 relative overflow-hidden">
                        <div className="absolute top-0 right-0 p-8 opacity-5"><ShieldCheck size={120}/></div>
                        <h3 className="text-xl font-black text-slate-900 mb-6 flex items-center gap-3 relative z-10"><ShieldCheck className="text-emerald-500"/> Security Gate</h3>
                        
                        <div className="space-y-6 relative z-10">
                            <div className="flex items-center gap-4">
                                <input type="checkbox" checked={securityConfig.verify_signature} onChange={e => setSecurityConfig({...securityConfig, verify_signature: e.target.checked})} className="w-5 h-5 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"/>
                                <div>
                                    <label className="text-sm font-bold text-slate-900 block">Verify Signature (HMAC)</label>
                                    <p className="text-xs text-slate-400">Validate `X-Signature` header matches payload hash.</p>
                                </div>
                            </div>

                            {securityConfig.verify_signature && (
                                <div className="grid grid-cols-2 gap-4 pl-9 animate-in slide-in-from-top-2">
                                    <div>
                                        <label className="text-[10px] font-black text-slate-400 uppercase">Header Key</label>
                                        <input value={securityConfig.header_key} onChange={e => setSecurityConfig({...securityConfig, header_key: e.target.value})} className="w-full mt-1 bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-bold"/>
                                    </div>
                                    <div>
                                        <label className="text-[10px] font-black text-slate-400 uppercase">Secret</label>
                                        <input type="password" value={securityConfig.secret} onChange={e => setSecurityConfig({...securityConfig, secret: e.target.value})} placeholder="Shared Secret" className="w-full mt-1 bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-bold"/>
                                    </div>
                                </div>
                            )}

                            <div className="pt-4 border-t border-slate-100">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1 mb-2 block">Idempotency Key (Optional)</label>
                                <input value={securityConfig.idempotency_key} onChange={e => setSecurityConfig({...securityConfig, idempotency_key: e.target.value})} placeholder="body.data.id" className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-sm font-mono font-medium outline-none"/>
                                <p className="text-[10px] text-slate-400 mt-2 px-1">Path to unique ID in payload. Prevents duplicate processing of the same event.</p>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {/* TAB: FLOW DESIGNER */}
            {activeTab === 'flow' && (
                <div className="flex h-full">
                    {/* CANVAS */}
                    <div className="flex-1 bg-slate-50 p-10 overflow-y-auto relative bg-[radial-gradient(#e2e8f0_1px,transparent_1px)] [background-size:20px_20px]">
                        <div className="max-w-3xl mx-auto space-y-6 pb-20">
                            
                            {/* START BLOCK */}
                            <div className="bg-slate-900 text-white p-6 rounded-2xl flex items-center justify-between shadow-lg">
                                <div className="flex items-center gap-4">
                                    <div className="w-12 h-12 bg-white/10 rounded-xl flex items-center justify-center backdrop-blur-sm"><Play size={24} className="text-emerald-400"/></div>
                                    <div>
                                        <h3 className="font-black text-lg">Request Received</h3>
                                        <p className="text-xs text-slate-400 opacity-80">Security Passed. Payload Available.</p>
                                    </div>
                                </div>
                                <div className="text-[10px] font-mono bg-black/30 px-3 py-1 rounded-lg">context.body</div>
                            </div>

                            {/* FLOW BLOCKS */}
                            {flow.map((block, idx) => (
                                <div key={block.id} className="relative pl-8 border-l-2 border-dashed border-slate-300 ml-6">
                                    <div className="absolute -left-[9px] top-1/2 -translate-y-1/2 w-4 h-4 bg-slate-300 rounded-full border-4 border-white"></div>
                                    
                                    <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm hover:shadow-md transition-all group relative">
                                        <button onClick={() => removeBlock(block.id)} className="absolute top-4 right-4 p-2 text-slate-300 hover:text-rose-500 opacity-0 group-hover:opacity-100 transition-all"><Trash2 size={16}/></button>
                                        
                                        {/* CONDITION BLOCK */}
                                        {block.type === 'condition' && (
                                            <div>
                                                <div className="flex items-center gap-3 mb-4 text-amber-600 font-black text-xs uppercase tracking-widest">
                                                    <GitBranch size={16}/> Condition (Logic)
                                                </div>
                                                <div className="flex gap-2 items-center">
                                                    <span className="font-bold text-sm text-slate-500">IF</span>
                                                    <input value={block.field} onChange={e => updateBlock(block.id, { field: e.target.value })} className="bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-xs font-mono font-bold w-1/3" placeholder="body.status"/>
                                                    <select value={block.operator} onChange={e => updateBlock(block.id, { operator: e.target.value })} className="bg-slate-50 border border-slate-200 rounded-lg px-2 py-2 text-xs font-bold outline-none">
                                                        <option value="eq">==</option><option value="neq">!=</option><option value="gt">&gt;</option><option value="lt">&lt;</option><option value="contains">contains</option>
                                                    </select>
                                                    <input value={block.value} onChange={e => updateBlock(block.id, { value: e.target.value })} className="bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-xs font-bold flex-1" placeholder="value"/>
                                                </div>
                                                <div className="mt-4 p-3 bg-amber-50 border border-amber-100 rounded-xl text-[10px] text-amber-800 font-medium text-center">
                                                    If true, execute nested steps (Not fully visualized in this linear editor version).
                                                </div>
                                            </div>
                                        )}

                                        {/* DATABASE ACTION */}
                                        {block.type === 'action_db' && (
                                            <div>
                                                <div className="flex items-center gap-3 mb-4 text-indigo-600 font-black text-xs uppercase tracking-widest">
                                                    <Database size={16}/> Database Operation
                                                </div>
                                                <div className="grid grid-cols-2 gap-4">
                                                    <div>
                                                        <label className="text-[9px] font-bold text-slate-400 uppercase">Operation</label>
                                                        <select value={block.operation} onChange={e => updateBlock(block.id, { operation: e.target.value as any })} className="w-full mt-1 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-xs font-bold outline-none">
                                                            <option value="INSERT">INSERT</option><option value="UPDATE">UPDATE</option><option value="DELETE">DELETE</option>
                                                        </select>
                                                    </div>
                                                    <div>
                                                        <label className="text-[9px] font-bold text-slate-400 uppercase">Target Table</label>
                                                        <select value={block.table} onChange={e => updateBlock(block.id, { table: e.target.value })} className="w-full mt-1 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-xs font-bold outline-none">
                                                            {tables.map(t => <option key={t} value={t}>{t}</option>)}
                                                        </select>
                                                    </div>
                                                </div>
                                                {/* JSON Data Mapper */}
                                                <div className="mt-4">
                                                    <label className="text-[9px] font-bold text-slate-400 uppercase mb-2 block">Data Mapper (JSON)</label>
                                                    <textarea 
                                                        value={JSON.stringify(block.data, null, 2)}
                                                        onChange={e => {
                                                            try {
                                                                const parsed = JSON.parse(e.target.value);
                                                                updateBlock(block.id, { data: parsed });
                                                            } catch {}
                                                        }}
                                                        className="w-full bg-slate-900 text-emerald-400 font-mono text-xs p-3 rounded-xl h-24 outline-none"
                                                        placeholder='{ "email": "{{body.user.email}}", "status": "active" }'
                                                    />
                                                </div>
                                                {block.operation !== 'INSERT' && (
                                                    <div className="mt-4 flex gap-2 items-center">
                                                        <span className="text-[10px] font-bold text-slate-500 uppercase">WHERE</span>
                                                        <input value={block.match_field} onChange={e => updateBlock(block.id, { match_field: e.target.value })} placeholder="id" className="bg-slate-50 border border-slate-200 rounded-lg px-2 py-1 text-xs font-mono font-bold w-20"/>
                                                        <span className="text-[10px] font-bold text-slate-500">=</span>
                                                        <input value={block.match_value} onChange={e => updateBlock(block.id, { match_value: e.target.value })} placeholder="{{body.id}}" className="bg-slate-50 border border-slate-200 rounded-lg px-2 py-1 text-xs font-mono font-bold flex-1"/>
                                                    </div>
                                                )}
                                            </div>
                                        )}

                                        {/* RPC ACTION */}
                                        {block.type === 'action_rpc' && (
                                            <div>
                                                <div className="flex items-center gap-3 mb-4 text-emerald-600 font-black text-xs uppercase tracking-widest">
                                                    <Zap size={16}/> Execute Function (RPC)
                                                </div>
                                                <div className="mb-4">
                                                    <label className="text-[9px] font-bold text-slate-400 uppercase">Function</label>
                                                    <select value={block.rpc_name} onChange={e => updateBlock(block.id, { rpc_name: e.target.value })} className="w-full mt-1 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 text-xs font-bold outline-none">
                                                        {rpcs.map(r => <option key={r} value={r}>{r}</option>)}
                                                    </select>
                                                </div>
                                                <div>
                                                    <label className="text-[9px] font-bold text-slate-400 uppercase mb-2 block">Arguments (JSON)</label>
                                                    <textarea 
                                                        value={JSON.stringify(block.rpc_args, null, 2)}
                                                        onChange={e => {
                                                            try {
                                                                const parsed = JSON.parse(e.target.value);
                                                                updateBlock(block.id, { rpc_args: parsed });
                                                            } catch {}
                                                        }}
                                                        className="w-full bg-slate-900 text-amber-400 font-mono text-xs p-3 rounded-xl h-24 outline-none"
                                                        placeholder='{ "user_id": "{{body.user_id}}" }'
                                                    />
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))}

                            {/* ADD BUTTONS */}
                            <div className="relative pl-8 border-l-2 border-dashed border-slate-300 ml-6 pb-10">
                                <div className="absolute -left-[9px] top-6 w-4 h-4 bg-white rounded-full border-4 border-slate-300"></div>
                                <div className="flex gap-4 pt-4">
                                    <button onClick={() => addBlock('action_db')} className="bg-white border border-slate-200 px-4 py-3 rounded-xl text-xs font-bold text-slate-600 hover:border-indigo-300 hover:text-indigo-600 transition-all shadow-sm flex items-center gap-2"><Plus size={14}/> Database Action</button>
                                    <button onClick={() => addBlock('condition')} className="bg-white border border-slate-200 px-4 py-3 rounded-xl text-xs font-bold text-slate-600 hover:border-amber-300 hover:text-amber-600 transition-all shadow-sm flex items-center gap-2"><GitBranch size={14}/> Logic Condition</button>
                                    <button onClick={() => addBlock('action_rpc')} className="bg-white border border-slate-200 px-4 py-3 rounded-xl text-xs font-bold text-slate-600 hover:border-emerald-300 hover:text-emerald-600 transition-all shadow-sm flex items-center gap-2"><Zap size={14}/> Call RPC</button>
                                </div>
                            </div>

                        </div>
                    </div>

                    {/* RIGHT SIDEBAR: HELPERS */}
                    <aside className="w-80 bg-white border-l border-slate-200 flex flex-col">
                        <div className="p-6 border-b border-slate-100 bg-slate-50/50">
                            <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] flex items-center gap-2"><Variable size={12}/> Variable Picker</h3>
                        </div>
                        <div className="flex-1 p-6 space-y-6 overflow-y-auto">
                            <div>
                                <h4 className="text-xs font-bold text-slate-900 mb-2">Request Body</h4>
                                <p className="text-[10px] text-slate-400 mb-2">Click to copy paths</p>
                                <div className="space-y-1">
                                    {['{{body}}', '{{body.data}}', '{{body.id}}', '{{body.type}}', '{{body.user.email}}'].map(v => (
                                        <button key={v} onClick={() => { navigator.clipboard.writeText(v); setNotification({type:'success', msg:'Copied!'}); }} className="block w-full text-left px-3 py-2 bg-slate-50 hover:bg-indigo-50 rounded-lg text-[10px] font-mono text-slate-600 hover:text-indigo-600 transition-colors border border-slate-100">
                                            {v}
                                        </button>
                                    ))}
                                </div>
                            </div>
                            <div>
                                <h4 className="text-xs font-bold text-slate-900 mb-2">Headers</h4>
                                <div className="space-y-1">
                                    {['{{headers.authorization}}', '{{headers.x-signature}}', '{{headers.content-type}}'].map(v => (
                                        <button key={v} onClick={() => { navigator.clipboard.writeText(v); setNotification({type:'success', msg:'Copied!'}); }} className="block w-full text-left px-3 py-2 bg-slate-50 hover:bg-emerald-50 rounded-lg text-[10px] font-mono text-slate-600 hover:text-emerald-600 transition-colors border border-slate-100">
                                            {v}
                                        </button>
                                    ))}
                                </div>
                            </div>
                            <div className="p-4 bg-indigo-50 rounded-xl border border-indigo-100">
                                <p className="text-[10px] text-indigo-800 leading-relaxed font-medium">
                                    Use these variables inside JSON fields or values. The engine will replace them with actual request data at runtime.
                                </p>
                            </div>
                        </div>
                    </aside>
                </div>
            )}
        </main>
    </div>
  );
};

export default IngressDesigner;
