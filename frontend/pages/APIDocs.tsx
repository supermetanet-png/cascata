
import React, { useState, useEffect } from 'react';
import { 
  BookOpen, Copy, Globe, Database, Code2, 
  ChevronRight, ChevronDown, Loader2, FileText, 
  Sparkles, Plus, Edit3, Search, Check, Terminal, Download,
  FileJson, Package, Blocks, Link as LinkIcon
} from 'lucide-react';

interface APIDocsProps {
  projectId: string;
}

const APIDocs: React.FC<APIDocsProps> = ({ projectId }) => {
  const [activeTab, setActiveTab] = useState<'reference' | 'guides' | 'libraries' | 'integrations'>('reference');
  const [spec, setSpec] = useState<any>(null);
  const [guides, setGuides] = useState<any[]>([]);
  const [selectedGuide, setSelectedGuide] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  
  // Search & Copy State
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);
  const [projectData, setProjectData] = useState<any>(null);

  // AI Generation State
  const [tables, setTables] = useState<string[]>([]);
  const [generating, setGenerating] = useState(false);
  const [showGenModal, setShowGenModal] = useState(false);

  useEffect(() => {
    fetchData();
  }, [projectId]);

  const fetchData = async () => {
    try {
      const token = localStorage.getItem('cascata_token');
      const headers = { 'Authorization': `Bearer ${token}` };
      
      const [specRes, guidesRes, tablesRes, projectRes] = await Promise.all([
        fetch(`/api/data/${projectId}/docs/openapi`, { headers }),
        fetch(`/api/data/${projectId}/docs/pages`, { headers }),
        fetch(`/api/data/${projectId}/tables`, { headers }),
        fetch('/api/control/projects', { headers })
      ]);
      
      setSpec(await specRes.json());
      const g = await guidesRes.json();
      setGuides(g);
      if(g.length > 0 && !selectedGuide) setSelectedGuide(g[0]);
      
      const t = await tablesRes.json();
      setTables(t.map((r: any) => r.name));

      const projects = await projectRes.json();
      const current = projects.find((p: any) => p.slug === projectId);
      setProjectData(current);
      
    } catch (e) {
      console.error("Failed to load docs");
    } finally {
      setLoading(false);
    }
  };

  const getBaseUrl = () => {
      if (projectData?.custom_domain) {
          return `https://${projectData.custom_domain}`;
      }
      return `${window.location.origin}/api/data/${projectId}`;
  };

  const getSwaggerUrl = () => {
      // The Swagger JSON is served at the root of the PostgREST compatible endpoint
      return `${getBaseUrl()}`;
  };

  // --- HELPER: Generate Curl ---
  const generateCurl = (method: string, path: string, requestBody: any) => {
      let baseUrl = getBaseUrl();
      if (baseUrl.endsWith('/') && path.startsWith('/')) baseUrl = baseUrl.slice(0, -1);

      const url = `${baseUrl}${path}`;
      const anonKey = projectData?.anon_key || '<YOUR_ANON_KEY>';
      
      let cmd = `curl -X ${method.toUpperCase()} "${url}" \\\n`;
      cmd += `  -H "apikey: ${anonKey}" \\\n`;
      cmd += `  -H "Content-Type: application/json"`;

      if (method !== 'get' && method !== 'delete') {
          cmd += ` \\\n  -d '{}'`;
      }
      return cmd;
  };

  const safeCopyToClipboard = (text: string, id: string = 'global') => {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text);
    } else {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        textArea.style.left = "-9999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
    }
    setCopiedUrl(id);
    setTimeout(() => setCopiedUrl(null), 2000);
  };

  const handleDownloadOpenAPI = () => {
      const blob = new Blob([JSON.stringify(spec, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `${projectId}-openapi.json`; a.click();
  };

  const togglePath = (path: string) => {
    const next = new Set(expandedPaths);
    if (next.has(path)) next.delete(path); else next.add(path);
    setExpandedPaths(next);
  };

  const handleGenerateDoc = async (tableName: string) => {
      setGenerating(true);
      try {
          const res = await fetch(`/api/data/${projectId}/ai/draft-doc`, {
              method: 'POST',
              headers: { 
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` 
              },
              body: JSON.stringify({ tableName })
          });
          
          if (!res.ok) throw new Error('Generation failed');
          const newDoc = await res.json();
          
          setGuides(prev => [newDoc, ...prev]);
          setSelectedGuide(newDoc);
          setShowGenModal(false);
          setActiveTab('guides');
      } catch (e) {
          alert("Failed to generate documentation. Ensure AI is configured in System Settings.");
      } finally {
          setGenerating(false);
      }
  };

  const filteredPaths = spec ? Object.entries(spec.paths).filter(([path]) => 
    path.toLowerCase().includes(searchQuery.toLowerCase())
  ) : [];

  const supabaseConfigCode = `
import { createClient } from '@supabase/supabase-js'

const supabaseUrl = '${getBaseUrl()}'
const supabaseKey = '${projectData?.anon_key || 'YOUR_ANON_KEY'}'

export const supabase = createClient(supabaseUrl, supabaseKey)
  `;

  if (loading) return <div className="p-20 flex justify-center"><Loader2 className="animate-spin text-indigo-600" /></div>;

  return (
    <div className="p-10 max-w-7xl mx-auto w-full space-y-10 pb-40">
      <header className="flex flex-col gap-8">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
            <div className="flex items-center gap-4">
            <div className="w-14 h-14 bg-emerald-600 text-white rounded-[1.5rem] flex items-center justify-center shadow-xl">
                <BookOpen size={28} />
            </div>
            <div>
                <h1 className="text-4xl font-black text-slate-900 tracking-tighter">Documentation</h1>
                <p className="text-slate-500 font-medium">Single Source of Truth</p>
            </div>
            </div>
            
            <div className="flex flex-wrap gap-4">
                <button onClick={handleDownloadOpenAPI} className="px-4 py-2.5 bg-slate-900 text-white rounded-xl text-xs font-black uppercase tracking-widest flex items-center gap-2 hover:bg-indigo-600 transition-all shadow-lg">
                    <FileJson size={16}/> OpenAPI (JSON)
                </button>
                
                <div className="flex bg-slate-100 p-1.5 rounded-2xl">
                    <button onClick={() => setActiveTab('reference')} className={`px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === 'reference' ? 'bg-white shadow-md text-indigo-600' : 'text-slate-400 hover:text-slate-600'}`}>API Reference</button>
                    <button onClick={() => setActiveTab('libraries')} className={`px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === 'libraries' ? 'bg-white shadow-md text-indigo-600' : 'text-slate-400 hover:text-slate-600'}`}>Libraries</button>
                    <button onClick={() => setActiveTab('integrations')} className={`px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === 'integrations' ? 'bg-white shadow-md text-indigo-600' : 'text-slate-400 hover:text-slate-600'}`}>Integrations</button>
                    <button onClick={() => setActiveTab('guides')} className={`px-6 py-2.5 rounded-xl text-xs font-black uppercase tracking-widest transition-all ${activeTab === 'guides' ? 'bg-white shadow-md text-indigo-600' : 'text-slate-400 hover:text-slate-600'}`}>Guides</button>
                </div>
            </div>
        </div>
        
        {activeTab === 'reference' && (
            <div className="bg-slate-900 text-white p-6 rounded-[2rem] flex items-center justify-between shadow-2xl">
            <div className="flex items-center gap-4">
                <Globe className="text-emerald-400" />
                <div>
                    <span className="text-[10px] font-black uppercase tracking-widest text-slate-400">Base URL</span>
                    <code className="block font-mono text-sm font-bold mt-1">
                        {getBaseUrl()}
                    </code>
                </div>
            </div>
            <button onClick={() => safeCopyToClipboard(getBaseUrl())} className="p-3 bg-white/10 hover:bg-white/20 rounded-xl transition-all">
                {copiedUrl === 'global' ? <Check size={18} className="text-emerald-400"/> : <Copy size={18}/>}
            </button>
            </div>
        )}
      </header>

      {/* REFERENCE TAB */}
      {activeTab === 'reference' && (
          <div className="space-y-6">
            <div className="relative">
                <Search className="absolute left-6 top-1/2 -translate-y-1/2 text-slate-400" size={18}/>
                <input 
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search endpoints..." 
                    className="w-full pl-14 pr-6 py-4 bg-white border border-slate-200 rounded-[2rem] text-sm font-bold outline-none focus:ring-2 focus:ring-indigo-500/20" 
                />
            </div>

            {filteredPaths.map(([path, methods]: [string, any]) => {
            const isExpanded = expandedPaths.has(path);
            return (
                <div key={path} className="bg-white border border-slate-200 rounded-[2.5rem] overflow-hidden shadow-sm hover:shadow-md transition-all">
                    <div 
                    onClick={() => togglePath(path)}
                    className="p-6 flex items-center justify-between cursor-pointer bg-slate-50 hover:bg-white transition-colors"
                    >
                    <div className="flex items-center gap-4">
                        {isExpanded ? <ChevronDown size={20} className="text-slate-400"/> : <ChevronRight size={20} className="text-slate-400"/>}
                        <span className="font-mono text-sm font-bold text-slate-700">{path}</span>
                    </div>
                    <div className="flex items-center gap-4">
                        <div className="flex gap-2">
                            {Object.keys(methods).map(m => (
                                <span key={m} className={`text-[9px] font-black uppercase px-2 py-1 rounded-lg ${m === 'get' ? 'bg-blue-100 text-blue-700' : m === 'post' ? 'bg-emerald-100 text-emerald-700' : 'bg-amber-100 text-amber-700'}`}>
                                    {m}
                                </span>
                            ))}
                        </div>
                    </div>
                    </div>

                    {isExpanded && (
                    <div className="p-8 border-t border-slate-100 space-y-12 animate-in slide-in-from-top-2">
                        {Object.entries(methods).map(([method, detail]: [string, any]) => {
                            const curlCommand = generateCurl(method, path, detail.requestBody);
                            return (
                            <div key={method} className="space-y-6">
                                <div className="flex items-center justify-between">
                                    <div className="flex items-center gap-3">
                                        <span className={`text-xs font-black uppercase px-3 py-1.5 rounded-xl ${method === 'get' ? 'bg-blue-600 text-white' : method === 'post' ? 'bg-emerald-600 text-white' : 'bg-amber-600 text-white'}`}>
                                            {method}
                                        </span>
                                        <span className="text-sm font-bold text-slate-900">{detail.summary}</span>
                                    </div>
                                    <button 
                                        onClick={() => safeCopyToClipboard(curlCommand, `${method}-${path}`)} 
                                        className="bg-slate-900 text-white hover:bg-indigo-600 px-4 py-2 rounded-xl flex items-center gap-2 text-[10px] font-bold uppercase transition-all shadow-lg"
                                    >
                                        {copiedUrl === `${method}-${path}` ? <Check size={14} className="text-emerald-400"/> : <Terminal size={14}/>} Copy cURL
                                    </button>
                                </div>
                                <div className="bg-slate-900 p-6 rounded-2xl border border-slate-800 shadow-inner">
                                    <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed overflow-x-auto">{curlCommand}</pre>
                                </div>
                            </div>
                        )})}
                    </div>
                    )}
                </div>
            );
            })}
          </div>
      )}

      {/* LIBRARIES TAB */}
      {activeTab === 'libraries' && (
          <div className="space-y-8 animate-in slide-in-from-right-4">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
                  <div className="bg-white border border-emerald-100 rounded-[3rem] p-10 shadow-xl relative overflow-hidden group">
                      <div className="absolute top-0 right-0 p-10 opacity-5 group-hover:scale-110 transition-transform"><Package size={180}/></div>
                      <div className="relative z-10">
                          <div className="flex items-center gap-4 mb-6">
                              <div className="w-16 h-16 bg-emerald-500 text-white rounded-2xl flex items-center justify-center shadow-lg"><Code2 size={32}/></div>
                              <div>
                                  <h3 className="text-2xl font-black text-slate-900 tracking-tight">Supabase JS</h3>
                                  <p className="text-xs font-bold text-emerald-600 uppercase tracking-widest bg-emerald-50 px-2 py-1 rounded inline-block mt-1">Fully Compatible</p>
                              </div>
                          </div>
                          <p className="text-sm text-slate-600 font-medium mb-8 leading-relaxed">
                              Use the official Supabase client to interact with your Cascata database. Our PostgREST compatibility layer ensures seamless integration.
                          </p>
                          <div className="space-y-6">
                              <div>
                                  <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1 mb-2 block">Installation</label>
                                  <code className="block bg-slate-900 text-emerald-400 p-4 rounded-2xl font-mono text-xs">npm install @supabase/supabase-js</code>
                              </div>
                              <div>
                                  <div className="flex justify-between items-center mb-2">
                                      <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1">Configuration (Copy & Paste)</label>
                                      <button onClick={() => safeCopyToClipboard(supabaseConfigCode.trim(), 'supacode')} className="text-emerald-600 text-[10px] font-bold uppercase hover:underline">
                                          {copiedUrl === 'supacode' ? 'Copied!' : 'Copy Code'}
                                      </button>
                                  </div>
                                  <pre className="bg-slate-900 text-slate-300 p-6 rounded-2xl font-mono text-xs overflow-auto leading-relaxed border border-slate-800 shadow-inner">
                                      {supabaseConfigCode.trim()}
                                  </pre>
                              </div>
                          </div>
                      </div>
                  </div>
                  <div className="bg-slate-50 border border-slate-200 rounded-[3rem] p-10 relative opacity-80 hover:opacity-100 transition-opacity">
                      <h3 className="text-xl font-black text-slate-900 mb-4 flex items-center gap-3"><Terminal size={20}/> Native Access</h3>
                      <p className="text-xs text-slate-500 font-medium mb-6">Directly use fetch or the lightweight Cascata SDK for raw performance.</p>
                      <pre className="bg-white border border-slate-200 p-6 rounded-2xl font-mono text-xs text-slate-600 leading-relaxed overflow-auto">
{`const res = await fetch('${getBaseUrl()}/tables/users/data', {
  headers: {
    'apikey': '${projectData?.anon_key}'
  }
});
const users = await res.json();`}
                      </pre>
                  </div>
              </div>
          </div>
      )}

      {/* NEW INTEGRATIONS TAB */}
      {activeTab === 'integrations' && (
          <div className="space-y-8 animate-in slide-in-from-right-4">
              <div className="bg-indigo-600 text-white rounded-[3rem] p-12 shadow-2xl relative overflow-hidden">
                  <div className="absolute top-0 right-0 p-16 opacity-10"><Blocks size={240}/></div>
                  <div className="relative z-10 flex flex-col gap-8">
                      <div>
                          <h2 className="text-3xl font-black tracking-tight flex items-center gap-4"><Blocks size={32} className="text-indigo-200"/> Low-Code Integration</h2>
                          <p className="text-indigo-100 font-medium mt-2 max-w-2xl">
                              Seamlessly connect FlutterFlow, AppSmith, Bubble, and Retool using our PostgREST compatible endpoint.
                          </p>
                      </div>

                      <div className="bg-white/10 backdrop-blur-md rounded-[2.5rem] p-8 border border-white/20">
                          <h4 className="text-sm font-bold uppercase tracking-widest text-indigo-200 mb-6">Connection Details</h4>
                          
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                              <div className="space-y-2">
                                  <label className="text-[10px] font-black uppercase tracking-widest text-white/60">Import URL (Swagger/OpenAPI)</label>
                                  <div className="flex gap-2">
                                      <code className="flex-1 bg-black/30 p-4 rounded-xl font-mono text-xs text-white truncate border border-white/10">
                                          {getSwaggerUrl()}
                                      </code>
                                      <button onClick={() => safeCopyToClipboard(getSwaggerUrl(), 'swagger')} className="p-3 bg-white text-indigo-600 rounded-xl hover:bg-indigo-50 transition-all font-bold">
                                          {copiedUrl === 'swagger' ? <Check size={16}/> : <Copy size={16}/>}
                                      </button>
                                  </div>
                                  <p className="text-[10px] text-white/50">Use this URL in "API Calls &gt; Import OpenAPI" inside FlutterFlow.</p>
                              </div>

                              <div className="space-y-2">
                                  <label className="text-[10px] font-black uppercase tracking-widest text-white/60">API Key Header</label>
                                  <div className="flex gap-2">
                                      <code className="flex-1 bg-black/30 p-4 rounded-xl font-mono text-xs text-white truncate border border-white/10">
                                          {projectData?.anon_key}
                                      </code>
                                      <button onClick={() => safeCopyToClipboard(projectData?.anon_key, 'apikey')} className="p-3 bg-white text-indigo-600 rounded-xl hover:bg-indigo-50 transition-all font-bold">
                                          {copiedUrl === 'apikey' ? <Check size={16}/> : <Copy size={16}/>}
                                      </button>
                                  </div>
                                  <p className="text-[10px] text-white/50">Header Name: <code className="bg-white/20 px-1 rounded">apikey</code></p>
                              </div>
                          </div>
                      </div>

                      <div className="flex gap-4">
                          <a href="https://docs.flutterflow.io/data/api-calls/openapi-import" target="_blank" rel="noreferrer" className="flex items-center gap-2 text-xs font-bold text-white hover:text-indigo-200 bg-white/10 px-4 py-2 rounded-xl transition-all">
                              <LinkIcon size={14}/> FlutterFlow Docs
                          </a>
                          <a href="https://docs.appsmith.com/connect-data/reference/rest-api" target="_blank" rel="noreferrer" className="flex items-center gap-2 text-xs font-bold text-white hover:text-indigo-200 bg-white/10 px-4 py-2 rounded-xl transition-all">
                              <LinkIcon size={14}/> AppSmith Docs
                          </a>
                      </div>
                  </div>
              </div>
          </div>
      )}

      {/* GUIDES TAB */}
      {activeTab === 'guides' && (
          <div className="flex gap-10 h-[600px]">
              <div className="w-64 shrink-0 flex flex-col gap-2">
                  <button onClick={() => setShowGenModal(true)} className="w-full bg-indigo-600 text-white py-3 rounded-xl font-black text-xs uppercase tracking-widest flex items-center justify-center gap-2 hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-100 mb-4">
                      <Sparkles size={14}/> Write with AI
                  </button>
                  {guides.map(g => (
                      <button 
                        key={g.id}
                        onClick={() => setSelectedGuide(g)}
                        className={`text-left px-4 py-3 rounded-xl text-sm font-bold transition-all ${selectedGuide?.id === g.id ? 'bg-white shadow-md text-indigo-600' : 'text-slate-500 hover:bg-white hover:shadow-sm'}`}
                      >
                          {g.title}
                      </button>
                  ))}
                  {guides.length === 0 && <p className="text-center text-slate-400 text-xs py-10 font-bold">No guides yet.</p>}
              </div>
              <div className="flex-1 bg-white border border-slate-200 rounded-[2.5rem] p-10 overflow-y-auto shadow-sm">
                  {selectedGuide ? (
                      <article className="prose prose-slate max-w-none">
                          <h1 className="text-3xl font-black tracking-tight mb-2">{selectedGuide.title}</h1>
                          <p className="text-xs text-slate-400 font-bold uppercase tracking-widest mb-8">Auto-Generated by Cascata Architect</p>
                          <div className="whitespace-pre-wrap font-medium text-slate-600 leading-relaxed text-sm">
                              {selectedGuide.content_markdown}
                          </div>
                      </article>
                  ) : (
                      <div className="h-full flex flex-col items-center justify-center text-slate-300 gap-4">
                          <FileText size={48}/>
                          <span className="font-black uppercase tracking-widest text-xs">Select a guide</span>
                      </div>
                  )}
              </div>
          </div>
      )}

      {/* GENERATE GUIDE MODAL */}
      {showGenModal && (
          <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-md z-[600] flex items-center justify-center p-8 animate-in zoom-in-95">
              <div className="bg-white rounded-[3rem] w-full max-w-md p-10 shadow-2xl">
                  <h3 className="text-2xl font-black text-slate-900 mb-6 flex items-center gap-3"><Sparkles className="text-indigo-500"/> AI Technical Writer</h3>
                  <div className="space-y-4 mb-8">
                      <p className="text-xs text-slate-500 font-bold">Select a table to generate a comprehensive integration guide.</p>
                      <div className="grid grid-cols-2 gap-3 max-h-60 overflow-y-auto">
                          {tables.map(t => (
                              <button key={t} onClick={() => handleGenerateDoc(t)} className="bg-slate-50 hover:bg-indigo-50 hover:text-indigo-700 text-slate-600 py-3 rounded-xl text-xs font-bold transition-all border border-slate-200 hover:border-indigo-200">
                                  {t}
                              </button>
                          ))}
                      </div>
                  </div>
                  <button onClick={() => setShowGenModal(false)} className="w-full py-4 text-xs font-black text-slate-400 uppercase tracking-widest hover:text-slate-600">Cancel</button>
                  {generating && <div className="absolute inset-0 bg-white/90 flex flex-col items-center justify-center z-10 rounded-[3rem]"><Loader2 className="animate-spin text-indigo-600 mb-4" size={40}/><span className="text-xs font-black uppercase tracking-widest animate-pulse">Writing Documentation...</span></div>}
              </div>
          </div>
      )}
    </div>
  );
};

export default APIDocs;
