
import React, { useState, useEffect } from 'react';
import { 
  Bell, Smartphone, Send, Plus, Trash2, 
  Loader2, CheckCircle2, AlertCircle, RefreshCw, 
  MessageSquare, User, Filter, Play, Clock, Zap
} from 'lucide-react';

const PushManager: React.FC<{ projectId: string }> = ({ projectId }) => {
  const [activeTab, setActiveTab] = useState<'campaign' | 'rules' | 'devices'>('campaign');
  const [loading, setLoading] = useState(true);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Data States
  const [devices, setDevices] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  
  // Campaign Form
  const [campaign, setCampaign] = useState({
      title: '',
      body: '',
      user_id: '', // Optional: specific user target
      data_json: '{}'
  });
  const [sending, setSending] = useState(false);

  // New Rule Form
  const [showNewRule, setShowNewRule] = useState(false);
  const [newRule, setNewRule] = useState({
      name: '',
      trigger_table: '',
      trigger_event: 'INSERT',
      title_template: '',
      body_template: '',
      recipient_column: 'user_id',
      conditions: [] as any[]
  });
  const [tables, setTables] = useState<string[]>([]);

  // Initialize
  useEffect(() => {
      fetchData();
  }, [projectId]);

  const fetchData = async () => {
      setLoading(true);
      try {
          const token = localStorage.getItem('cascata_token');
          const headers = { 'Authorization': `Bearer ${token}` };

          const [rulesRes, tablesRes] = await Promise.all([
              fetch(`/api/data/${projectId}/push/rules`, { headers }),
              fetch(`/api/data/${projectId}/tables`, { headers })
          ]);

          setRules(await rulesRes.json());
          
          const tbls = await tablesRes.json();
          setTables(tbls.map((t: any) => t.name));

          // Fetch devices (using existing auth endpoint logic or direct query via RPC if needed)
          // For now, we simulate fetching devices via a custom SQL query using the generic endpoint
          // In a real scenario, we might want a dedicated endpoint for devices list
          const devicesRes = await fetch(`/api/data/${projectId}/query`, {
              method: 'POST',
              headers: { ...headers, 'Content-Type': 'application/json' },
              body: JSON.stringify({ sql: "SELECT * FROM auth.user_devices ORDER BY last_active_at DESC LIMIT 50" })
          });
          const devData = await devicesRes.json();
          setDevices(devData.rows || []);

      } catch (e) {
          console.error("Failed to load push data", e);
      } finally {
          setLoading(false);
      }
  };

  const handleSendCampaign = async () => {
      if (!campaign.title || !campaign.body) {
          setError("Título e Mensagem são obrigatórios.");
          return;
      }
      
      setSending(true);
      try {
          const token = localStorage.getItem('cascata_token');
          // Se user_id estiver vazio, isto seria um Broadcast. 
          // O endpoint atual 'send' espera um user_id único.
          // Para broadcast real, o backend precisaria de um loop.
          // Aqui vamos assumir envio único para teste ou implementar lógica de broadcast no backend depois.
          
          if (!campaign.user_id) throw new Error("Para teste manual, defina um User ID (UUID).");

          let dataPayload = {};
          try { dataPayload = JSON.parse(campaign.data_json); } catch(e) {}

          const res = await fetch(`/api/data/${projectId}/push/send`, {
              method: 'POST',
              headers: { 
                  'Authorization': `Bearer ${token}`,
                  'Content-Type': 'application/json'
              },
              body: JSON.stringify({
                  user_id: campaign.user_id,
                  title: campaign.title,
                  body: campaign.body,
                  data: dataPayload
              })
          });

          if (!res.ok) {
              const err = await res.json();
              throw new Error(err.error || "Falha no envio.");
          }

          setSuccess("Notificação enviada!");
          setTimeout(() => setSuccess(null), 3000);
      } catch (e: any) {
          setError(e.message);
          setTimeout(() => setError(null), 3000);
      } finally {
          setSending(false);
      }
  };

  const handleCreateRule = async () => {
      try {
          const token = localStorage.getItem('cascata_token');
          await fetch(`/api/data/${projectId}/push/rules`, {
              method: 'POST',
              headers: { 
                  'Authorization': `Bearer ${token}`,
                  'Content-Type': 'application/json'
              },
              body: JSON.stringify(newRule)
          });
          setSuccess("Regra criada.");
          setShowNewRule(false);
          fetchData();
          setTimeout(() => setSuccess(null), 3000);
      } catch (e) {
          setError("Erro ao salvar regra.");
      }
  };

  const handleDeleteRule = async (id: string) => {
      if(!confirm("Deletar esta regra?")) return;
      try {
          const token = localStorage.getItem('cascata_token');
          await fetch(`/api/data/${projectId}/push/rules/${id}`, {
              method: 'DELETE',
              headers: { 'Authorization': `Bearer ${token}` }
          });
          fetchData();
      } catch(e) {}
  };

  if (loading) return <div className="p-20 flex justify-center"><Loader2 className="animate-spin text-indigo-600"/></div>;

  return (
    <div className="p-8 lg:p-12 max-w-6xl mx-auto w-full space-y-12 pb-40">
        {(success || error) && (
            <div className={`fixed top-8 left-1/2 -translate-x-1/2 z-[600] px-6 py-4 rounded-full shadow-2xl flex items-center gap-3 animate-in slide-in-from-top-4 ${error ? 'bg-rose-600 text-white' : 'bg-emerald-600 text-white'}`}>
                {error ? <AlertCircle size={18}/> : <CheckCircle2 size={18}/>}
                <span className="text-xs font-bold">{success || error}</span>
            </div>
        )}

        <header className="flex flex-col md:flex-row md:items-end justify-between gap-8">
            <div className="flex items-center gap-6">
                <div className="w-14 h-14 bg-amber-500 text-white rounded-[1.5rem] flex items-center justify-center shadow-xl">
                    <Smartphone size={28} />
                </div>
                <div>
                    <h2 className="text-4xl font-black text-slate-900 tracking-tighter">Push Engine</h2>
                    <p className="text-slate-500 font-medium mt-1">Mobile Notification Orchestrator</p>
                </div>
            </div>
            
            <div className="flex bg-slate-100 p-1.5 rounded-2xl">
                <button onClick={() => setActiveTab('campaign')} className={`px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === 'campaign' ? 'bg-white shadow-md text-indigo-600' : 'text-slate-400 hover:text-slate-600'}`}>Studio</button>
                <button onClick={() => setActiveTab('rules')} className={`px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === 'rules' ? 'bg-white shadow-md text-indigo-600' : 'text-slate-400 hover:text-slate-600'}`}>Automation</button>
                <button onClick={() => setActiveTab('devices')} className={`px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === 'devices' ? 'bg-white shadow-md text-indigo-600' : 'text-slate-400 hover:text-slate-600'}`}>Devices</button>
            </div>
        </header>

        {activeTab === 'campaign' && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-10">
                <div className="lg:col-span-2 space-y-8">
                    <div className="bg-white border border-slate-200 rounded-[3rem] p-10 shadow-sm">
                        <h3 className="text-xl font-black text-slate-900 mb-6 flex items-center gap-2"><Send size={20} className="text-indigo-600"/> Compose Notification</h3>
                        <div className="space-y-6">
                            <div className="space-y-2">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Campaign Title</label>
                                <input 
                                    value={campaign.title}
                                    onChange={e => setCampaign({...campaign, title: e.target.value})}
                                    placeholder="Hello World!"
                                    className="w-full bg-slate-50 border border-slate-100 rounded-2xl py-4 px-6 text-lg font-bold text-slate-900 outline-none focus:ring-4 focus:ring-indigo-500/10 placeholder:text-slate-300"
                                />
                            </div>
                            <div className="space-y-2">
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Message Body</label>
                                <textarea 
                                    value={campaign.body}
                                    onChange={e => setCampaign({...campaign, body: e.target.value})}
                                    placeholder="Type your message here..."
                                    className="w-full bg-slate-50 border border-slate-100 rounded-2xl py-4 px-6 text-sm font-medium text-slate-600 outline-none focus:ring-4 focus:ring-indigo-500/10 min-h-[120px] resize-none"
                                />
                            </div>
                            <div className="grid grid-cols-2 gap-6">
                                <div className="space-y-2">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Target User ID (UUID)</label>
                                    <input 
                                        value={campaign.user_id}
                                        onChange={e => setCampaign({...campaign, user_id: e.target.value})}
                                        placeholder="0000-0000..."
                                        className="w-full bg-slate-50 border border-slate-100 rounded-2xl py-3 px-4 text-xs font-mono font-bold text-slate-600 outline-none"
                                    />
                                </div>
                                <div className="space-y-2">
                                    <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Data Payload (JSON)</label>
                                    <input 
                                        value={campaign.data_json}
                                        onChange={e => setCampaign({...campaign, data_json: e.target.value})}
                                        placeholder='{"route": "/home"}'
                                        className="w-full bg-slate-50 border border-slate-100 rounded-2xl py-3 px-4 text-xs font-mono font-bold text-slate-600 outline-none"
                                    />
                                </div>
                            </div>
                            <div className="pt-4 flex justify-end">
                                <button 
                                    onClick={handleSendCampaign}
                                    disabled={sending}
                                    className="bg-indigo-600 text-white px-8 py-4 rounded-2xl font-black text-xs uppercase tracking-widest hover:bg-indigo-700 transition-all shadow-xl flex items-center gap-2"
                                >
                                    {sending ? <Loader2 size={16} className="animate-spin"/> : <Send size={16}/>} Send Now
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="space-y-6">
                    <div className="bg-slate-900 rounded-[3rem] p-8 text-white relative overflow-hidden shadow-2xl">
                        <div className="relative z-10">
                            <h4 className="font-black text-lg mb-2">Live Preview</h4>
                            <div className="bg-white/10 backdrop-blur-md rounded-2xl p-4 border border-white/10 mt-6">
                                <div className="flex items-start gap-3">
                                    <div className="w-10 h-10 bg-indigo-500 rounded-xl flex items-center justify-center shrink-0">
                                        <Bell size={20} className="text-white"/>
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex justify-between items-baseline mb-1">
                                            <span className="font-bold text-sm text-white truncate">{campaign.title || 'Notification Title'}</span>
                                            <span className="text-[10px] text-white/50">now</span>
                                        </div>
                                        <p className="text-xs text-white/80 line-clamp-3">{campaign.body || 'Notification body content will appear here...'}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        )}

        {activeTab === 'rules' && (
            <div className="space-y-8">
                <div className="flex justify-between items-center">
                    <h3 className="text-xl font-black text-slate-900 tracking-tight flex items-center gap-3"><Zap size={24} className="text-amber-500"/> Automation Rules</h3>
                    <button onClick={() => setShowNewRule(true)} className="bg-indigo-600 text-white px-6 py-3 rounded-2xl font-black text-xs uppercase tracking-widest hover:bg-indigo-700 transition-all shadow-lg flex items-center gap-2"><Plus size={16}/> New Rule</button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {rules.length === 0 && <div className="col-span-full py-20 text-center text-slate-400 font-bold uppercase text-xs">No active rules defined</div>}
                    {rules.map(rule => (
                        <div key={rule.id} className="bg-white border border-slate-200 rounded-[2.5rem] p-8 hover:shadow-xl transition-all group">
                            <div className="flex justify-between items-start mb-6">
                                <div className="flex items-center gap-4">
                                    <div className="w-12 h-12 bg-amber-50 text-amber-600 rounded-2xl flex items-center justify-center shadow-inner">
                                        <Zap size={24}/>
                                    </div>
                                    <div>
                                        <h4 className="font-black text-lg text-slate-900">{rule.name}</h4>
                                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mt-1">
                                            ON {rule.trigger_event} {rule.trigger_table}
                                        </p>
                                    </div>
                                </div>
                                <button onClick={() => handleDeleteRule(rule.id)} className="p-2 text-slate-300 hover:text-rose-600 rounded-xl transition-colors"><Trash2 size={18}/></button>
                            </div>
                            <div className="bg-slate-50 rounded-2xl p-4 border border-slate-100 mb-4 space-y-2">
                                <div className="flex items-center gap-2 text-xs font-bold text-slate-600">
                                    <span className="text-indigo-500">Subject:</span> {rule.title_template}
                                </div>
                                <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
                                    <span className="text-indigo-500 font-bold">Body:</span> {rule.body_template}
                                </div>
                            </div>
                            <div className="flex justify-between items-center text-[10px] font-bold text-slate-400 uppercase tracking-widest">
                                <span>Target: {rule.recipient_column}</span>
                                <span className="bg-emerald-50 text-emerald-600 px-2 py-1 rounded">Active</span>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        )}

        {activeTab === 'devices' && (
            <div className="bg-white border border-slate-200 rounded-[3rem] p-10 shadow-sm overflow-hidden">
                <table className="w-full text-left border-collapse">
                    <thead>
                        <tr className="bg-slate-50/50 border-b border-slate-100">
                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">User ID</th>
                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">Platform</th>
                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest">Last Active</th>
                            <th className="px-6 py-4 text-[10px] font-black text-slate-400 uppercase tracking-widest text-right">Status</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-50">
                        {devices.map(d => (
                            <tr key={d.id} className="hover:bg-slate-50 transition-colors">
                                <td className="px-6 py-4">
                                    <div className="flex items-center gap-3">
                                        <div className="w-8 h-8 bg-indigo-50 text-indigo-600 rounded-lg flex items-center justify-center"><User size={14}/></div>
                                        <code className="text-xs font-mono font-bold text-slate-600">{d.user_id.substring(0, 8)}...</code>
                                    </div>
                                </td>
                                <td className="px-6 py-4"><span className="text-xs font-bold text-slate-700 capitalize">{d.platform}</span></td>
                                <td className="px-6 py-4"><span className="text-xs text-slate-500">{new Date(d.last_active_at).toLocaleDateString()}</span></td>
                                <td className="px-6 py-4 text-right">
                                    <span className={`px-2 py-1 rounded text-[9px] font-black uppercase tracking-widest ${d.is_active ? 'bg-emerald-50 text-emerald-600' : 'bg-slate-100 text-slate-400'}`}>
                                        {d.is_active ? 'Active' : 'Inactive'}
                                    </span>
                                </td>
                            </tr>
                        ))}
                        {devices.length === 0 && <tr><td colSpan={4} className="py-10 text-center text-slate-400 text-xs font-bold uppercase">No devices registered</td></tr>}
                    </tbody>
                </table>
            </div>
        )}

        {/* NEW RULE MODAL */}
        {showNewRule && (
            <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-[500] flex items-center justify-center p-8 animate-in zoom-in-95">
                <div className="bg-white rounded-[3rem] w-full max-w-lg p-10 shadow-2xl border border-slate-200 overflow-y-auto max-h-[90vh]">
                    <h3 className="text-2xl font-black text-slate-900 mb-6">Create Automation Rule</h3>
                    <div className="space-y-4">
                        <div>
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Rule Name</label>
                            <input value={newRule.name} onChange={e => setNewRule({...newRule, name: e.target.value})} className="w-full bg-slate-50 border-none rounded-xl py-3 px-4 text-sm font-bold outline-none" placeholder="Order Shipped Alert"/>
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Trigger Table</label>
                                <select value={newRule.trigger_table} onChange={e => setNewRule({...newRule, trigger_table: e.target.value})} className="w-full bg-slate-50 border-none rounded-xl py-3 px-4 text-xs font-bold outline-none">
                                    <option value="">Select Table...</option>
                                    {tables.map(t => <option key={t} value={t}>{t}</option>)}
                                </select>
                            </div>
                            <div>
                                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Event</label>
                                <select value={newRule.trigger_event} onChange={e => setNewRule({...newRule, trigger_event: e.target.value})} className="w-full bg-slate-50 border-none rounded-xl py-3 px-4 text-xs font-bold outline-none">
                                    <option value="INSERT">INSERT</option>
                                    <option value="UPDATE">UPDATE</option>
                                    <option value="DELETE">DELETE</option>
                                </select>
                            </div>
                        </div>
                        <div>
                            <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Recipient Column (User ID)</label>
                            <input value={newRule.recipient_column} onChange={e => setNewRule({...newRule, recipient_column: e.target.value})} className="w-full bg-slate-50 border-none rounded-xl py-3 px-4 text-sm font-mono font-bold outline-none" placeholder="user_id"/>
                        </div>
                        <div className="p-4 bg-indigo-50 rounded-2xl space-y-3">
                            <h4 className="text-xs font-black text-indigo-900 uppercase">Notification Template</h4>
                            <div>
                                <input value={newRule.title_template} onChange={e => setNewRule({...newRule, title_template: e.target.value})} className="w-full bg-white border-none rounded-xl py-2 px-3 text-xs font-bold outline-none mb-2" placeholder="Title (e.g. Order {{id}})"/>
                                <textarea value={newRule.body_template} onChange={e => setNewRule({...newRule, body_template: e.target.value})} className="w-full bg-white border-none rounded-xl py-2 px-3 text-xs font-medium outline-none h-20 resize-none" placeholder="Body (e.g. Your status is {{status}})"/>
                            </div>
                        </div>
                        <div className="flex gap-4 pt-4">
                            <button onClick={() => setShowNewRule(false)} className="flex-1 py-4 text-xs font-black text-slate-400 uppercase tracking-widest hover:bg-slate-50 rounded-xl">Cancel</button>
                            <button onClick={handleCreateRule} className="flex-[2] bg-indigo-600 text-white py-4 rounded-xl text-xs font-black uppercase tracking-widest hover:bg-indigo-700 shadow-lg">Save Rule</button>
                        </div>
                    </div>
                </div>
            </div>
        )}
    </div>
  );
};

export default PushManager;
