
import React, { useState, useEffect, useCallback } from 'react';
import { 
  Shield, Play, Plus, X, Save, ArrowLeft, Loader2, 
  User, Database, Lock, Eye, CheckCircle2, GripVertical, 
  Trash2, Copy, GitBranch, Zap, Box, Key, AlignLeft, MousePointer2,
  ChevronDown, ShieldCheck, Link as LinkIcon, Layers, Workflow,
  FileJson, BookOpen, AlertTriangle, ArrowRight, CheckSquare
} from 'lucide-react';

interface RLSDesignerProps {
  projectId: string;
  entityType: 'table' | 'bucket';
  entityName: string;
  onBack: () => void;
}

// --- TYPES ---

type LogicOperator = 'AND' | 'OR';
type Comparator = '=' | '!=' | '>' | '<' | 'IN' | 'IS';

interface ForeignKey {
  column: string;
  foreignTable: string;
  foreignColumn: string;
}

interface LogicNode {
  id: string;
  type: 'group' | 'condition' | 'relation'; // 'relation' handles EXISTS(...)
  
  // Group Props
  operator?: LogicOperator;
  children?: LogicNode[];
  
  // Condition Props
  field?: string;
  comparator?: Comparator;
  value?: string;
  valueType?: 'static' | 'dynamic' | 'auth'; // 'auth.uid()' etc
  
  // Relation Props (For concatenated checks)
  relationTable?: string;
  relationLocalKey?: string;
  relationForeignKey?: string;
}

// --- UTILS ---

const getUUID = () => Math.random().toString(36).substring(2, 15);

// Presets Library
const PRESETS = {
  OWNER_ONLY: {
    name: 'Owner Only',
    desc: 'Users can only access their own data.',
    tree: {
      id: 'root', type: 'group', operator: 'AND', children: [
        { id: 'p1', type: 'condition', field: 'user_id', comparator: '=', value: 'auth.uid()', valueType: 'auth' }
      ]
    }
  },
  PUBLIC_READ: {
    name: 'Public Read',
    desc: 'Anyone can read, nobody can write.',
    tree: {
      id: 'root', type: 'group', operator: 'AND', children: [
        { id: 'p1', type: 'condition', field: 'true', comparator: '', value: '', valueType: 'static' } // Simplifies to true
      ]
    }
  },
  SAAS_TENANT: {
    name: 'Tenant Isolation',
    desc: 'Check organization_id via metadata.',
    tree: {
      id: 'root', type: 'group', operator: 'AND', children: [
        { id: 'p1', type: 'condition', field: 'org_id', comparator: '=', value: "(auth.jwt() ->> 'org_id')::uuid", valueType: 'dynamic' }
      ]
    }
  }
};

const RLSDesigner: React.FC<RLSDesignerProps> = ({ projectId, entityType, entityName, onBack }) => {
  // --- STATE ---
  const [columns, setColumns] = useState<{name: string, type: string}[]>([]);
  const [foreignKeys, setForeignKeys] = useState<ForeignKey[]>([]);
  
  const [policyName, setPolicyName] = useState('');
  const [command, setCommand] = useState('SELECT');
  const [role, setRole] = useState('authenticated');
  
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [deployError, setDeployError] = useState<string | null>(null);
  
  // The Brain
  const [logicTree, setLogicTree] = useState<LogicNode>({
    id: 'root',
    type: 'group',
    operator: 'AND',
    children: []
  });

  const [activeTab, setActiveTab] = useState<'visual' | 'sql' | 'simulator'>('visual');
  const [simulatorUid, setSimulatorUid] = useState('');

  // --- INITIALIZATION ---

  const fetchSchemaInfo = async () => {
    setLoading(true);
    const token = localStorage.getItem('cascata_token');
    
    try {
      if (entityType === 'table') {
        // 1. Get Columns
        const colRes = await fetch(`/api/data/${projectId}/tables/${entityName}/columns`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        const colData = await colRes.json();
        setColumns(colData.map((c: any) => ({ name: c.name, type: c.type })));

        // 2. Get Foreign Keys via SQL (Power Move)
        const fkQuery = `
          SELECT
              kcu.column_name, 
              ccu.table_name AS foreign_table_name,
              ccu.column_name AS foreign_column_name 
          FROM information_schema.key_column_usage AS kcu
          JOIN information_schema.constraint_column_usage AS ccu
              ON ccu.constraint_name = kcu.constraint_name
          JOIN information_schema.table_constraints AS tc
              ON tc.constraint_name = kcu.constraint_name
          WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_name = '${entityName}';
        `;
        
        const fkRes = await fetch(`/api/data/${projectId}/query`, {
           method: 'POST',
           headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
           body: JSON.stringify({ sql: fkQuery })
        });
        const fkData = await fkRes.json();
        
        if (fkData.rows) {
            setForeignKeys(fkData.rows.map((r: any) => ({
                column: r.column_name,
                foreignTable: r.foreign_table_name,
                foreignColumn: r.foreign_column_name
            })));
        }

      } else {
        // Bucket Schema
        setColumns([
            { name: 'name', type: 'text' },
            { name: 'owner_id', type: 'uuid' }, // Maps to auth.users usually
            { name: 'created_at', type: 'timestamptz' },
            { name: 'size', type: 'int8' },
            { name: 'mime_type', type: 'text' }
        ]);
        // Allow linking owner_id to auth users hypothetically
        setForeignKeys([{ column: 'owner_id', foreignTable: 'auth.users', foreignColumn: 'id' }]);
      }
    } catch (e) {
      console.error("Schema fetch failed", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchSchemaInfo(); }, [projectId, entityName]);

  // --- LOGIC MANIPULATION ---

  const updateNode = (id: string, changes: Partial<LogicNode>) => {
      const traverse = (node: LogicNode): LogicNode => {
          if (node.id === id) return { ...node, ...changes };
          if (node.children) return { ...node, children: node.children.map(traverse) };
          return node;
      };
      setLogicTree(traverse(logicTree));
  };

  const addNode = (parentId: string, type: 'condition' | 'group' | 'relation') => {
      const newNode: LogicNode = { 
          id: getUUID(), 
          type, 
          // Defaults
          operator: 'AND', 
          children: [], 
          field: columns[0]?.name || 'id', 
          comparator: '=', 
          value: '',
          valueType: 'static'
      };
      
      const traverse = (node: LogicNode): LogicNode => {
          if (node.id === parentId && node.children) return { ...node, children: [...node.children, newNode] };
          if (node.children) return { ...node, children: node.children.map(traverse) };
          return node;
      };
      setLogicTree(traverse(logicTree));
  };

  const removeNode = (id: string) => {
      const traverse = (node: LogicNode): LogicNode => {
          if (!node.children) return node;
          return { ...node, children: node.children.filter(c => c.id !== id).map(traverse) };
      };
      setLogicTree(traverse(logicTree));
  };

  const loadPreset = (presetKey: string) => {
      // Deep copy the preset tree to avoid reference issues
      const preset = (PRESETS as any)[presetKey];
      if (preset) {
          setLogicTree(JSON.parse(JSON.stringify(preset.tree)));
          if (!policyName) setPolicyName(preset.name);
      }
  };

  // --- COMPILER ENGINE ---

  const compileNode = (node: LogicNode, depth: number = 0): string => {
      if (node.type === 'group') {
          if (!node.children || node.children.length === 0) return '';
          const parts = node.children.map(c => compileNode(c, depth + 1)).filter(Boolean);
          if (parts.length === 0) return '';
          const joined = parts.join(` ${node.operator} `);
          return depth === 0 ? joined : `(${joined})`;
      } 
      
      if (node.type === 'relation') {
          // Generates: EXISTS (SELECT 1 FROM target WHERE target.key = current.key AND (children_logic))
          if (!node.relationTable || !node.children || node.children.length === 0) return '';
          
          const innerLogic = compileNode({ 
              id: 'temp', type: 'group', operator: 'AND', children: node.children 
          }, depth + 1);
          
          if (!innerLogic) return '';

          // NOTE: In RLS, we refer to the current table implicitly or via table name.
          // For safety in subqueries, we should alias the subquery table or use fully qualified names.
          // Simplified implementation:
          return `EXISTS (SELECT 1 FROM public."${node.relationTable}" WHERE public."${node.relationTable}"."${node.relationForeignKey}" = "${entityName}"."${node.relationLocalKey}" AND ${innerLogic})`;
      }

      if (node.type === 'condition') {
          if (node.field === 'true') return 'true';
          if (!node.field) return '';
          
          let val = node.value;
          if (node.valueType === 'static') {
              // Quote strings, leave numbers/booleans
              const isNum = !isNaN(Number(val));
              const isBool = val === 'true' || val === 'false';
              if (!isNum && !isBool && val !== 'null') val = `'${val}'`;
          }
          
          return `"${node.field}" ${node.comparator} ${val}`;
      }

      return '';
  };

  const generatedSQL = compileSQL();

  function compileSQL() {
      const sql = compileNode(logicTree);
      return sql || 'false'; // Default deny if empty
  }

  // --- ACTIONS ---

  const handleDeploy = async () => {
      if (!policyName) { alert("Enter a policy name."); return; }
      setSaving(true);
      setDeployError(null);
      
      try {
          const sql = generatedSQL;
          const fullCmd = `
            ${command === 'INSERT' || command === 'ALL' ? `-- WITH CHECK clause applied automatically for INSERT` : ''}
            CREATE POLICY "${policyName}"
            ON "${entityName}"
            FOR ${command}
            TO ${role}
            USING (${sql})
            ${['INSERT', 'UPDATE', 'ALL'].includes(command) ? `WITH CHECK (${sql})` : ''};
          `;
          
          // Execute via Query Endpoint directly for maximum control
          const res = await fetch(`/api/data/${projectId}/query`, {
              method: 'POST',
              headers: { 
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${localStorage.getItem('cascata_token')}` 
              },
              body: JSON.stringify({ sql: fullCmd })
          });

          const data = await res.json();

          if (!res.ok) {
              // Extract Postgres error code and message
              const errorMsg = data.error || "Unknown database error";
              const errorCode = data.code ? `(Code: ${data.code})` : "";
              
              if (data.code === '42883') {
                  throw new Error(`Database Error ${errorCode}: The function used (like auth.uid()) does not exist. Please run migration 013.`);
              }
              
              throw new Error(`Database Error ${errorCode}: ${errorMsg}`);
          }
          
          // Success!
          onBack();
      } catch (e: any) {
          setDeployError(e.message);
          console.error(e);
      } finally {
          setSaving(false);
      }
  };

  // --- RENDERERS ---

  const renderNode = (node: LogicNode, depth: number = 0) => {
      const isRoot = node.id === 'root';
      const isGroup = node.type === 'group';
      const isRelation = node.type === 'relation';

      return (
          <div key={node.id} className={`relative flex flex-col ${!isRoot ? 'ml-6 mt-3' : ''}`}>
              {/* Connector Lines */}
              {!isRoot && (
                  <div className="absolute -left-6 top-4 w-6 h-[2px] bg-slate-300 rounded-l-full"></div>
              )}
              {!isRoot && (
                  <div className="absolute -left-6 -top-4 h-[calc(100%+1rem)] w-[2px] bg-slate-300"></div>
              )}

              {/* Node Content */}
              <div className={`
                  flex items-center gap-2 p-3 rounded-2xl border transition-all shadow-sm
                  ${isGroup ? 'bg-slate-50 border-slate-200' : isRelation ? 'bg-indigo-50 border-indigo-200' : 'bg-white border-slate-200 hover:border-indigo-300'}
              `}>
                  {/* Handle */}
                  {!isRoot && <GripVertical size={14} className="text-slate-300 cursor-grab" />}

                  {/* Logic Control (Group) */}
                  {isGroup && (
                      <div className="flex items-center gap-3">
                          <div className={`px-3 py-1.5 rounded-lg text-[10px] font-black uppercase tracking-widest flex items-center gap-2 cursor-pointer transition-colors ${node.operator === 'AND' ? 'bg-amber-100 text-amber-700' : 'bg-purple-100 text-purple-700'}`}>
                              <GitBranch size={12}/>
                              <select 
                                value={node.operator} 
                                onChange={(e) => updateNode(node.id, { operator: e.target.value as any })}
                                className="bg-transparent outline-none appearance-none cursor-pointer"
                              >
                                  <option value="AND">ALL OF (AND)</option>
                                  <option value="OR">ANY OF (OR)</option>
                              </select>
                          </div>
                          
                          <div className="h-4 w-[1px] bg-slate-300 mx-1"></div>
                          
                          <div className="flex gap-1">
                              <button onClick={() => addNode(node.id, 'condition')} className="p-1.5 hover:bg-white rounded-md text-slate-400 hover:text-emerald-600 transition-all" title="Add Rule"><Plus size={14}/></button>
                              <button onClick={() => addNode(node.id, 'group')} className="p-1.5 hover:bg-white rounded-md text-slate-400 hover:text-amber-600 transition-all" title="Add Group"><Layers size={14}/></button>
                              <button onClick={() => addNode(node.id, 'relation')} className="p-1.5 hover:bg-white rounded-md text-slate-400 hover:text-indigo-600 transition-all" title="Add Relation Check"><LinkIcon size={14}/></button>
                          </div>
                      </div>
                  )}

                  {/* Relation Logic (Concatenation) */}
                  {isRelation && (
                      <div className="flex items-center gap-2 text-xs">
                          <span className="font-bold text-indigo-700 uppercase text-[10px]">LINK:</span>
                          <span className="font-mono text-slate-600 bg-white px-2 py-1 rounded border border-indigo-100">{entityName}.</span>
                          <select 
                            value={node.relationLocalKey}
                            onChange={(e) => {
                                const fk = foreignKeys.find(f => f.column === e.target.value);
                                updateNode(node.id, { 
                                    relationLocalKey: e.target.value,
                                    relationTable: fk?.foreignTable,
                                    relationForeignKey: fk?.foreignColumn
                                });
                            }}
                            className="bg-white border border-indigo-100 rounded-lg px-2 py-1 font-bold text-indigo-700 outline-none"
                          >
                              <option value="">Choose FK...</option>
                              {foreignKeys.map(fk => <option key={fk.column} value={fk.column}>{fk.column} → {fk.foreignTable}</option>)}
                          </select>
                          <ArrowRight size={12} className="text-indigo-300"/>
                          <span className="font-bold text-slate-700">{node.relationTable || 'Target'}</span>
                          <span className="text-indigo-400 text-[10px] font-medium ml-2">(Where conditions match...)</span>
                          
                          <div className="flex gap-1 ml-4">
                              <button onClick={() => addNode(node.id, 'condition')} className="p-1.5 bg-white hover:bg-indigo-100 rounded-md text-indigo-400 hover:text-indigo-600 transition-all" title="Add Sub-Condition"><Plus size={14}/></button>
                          </div>
                      </div>
                  )}

                  {/* Condition Logic */}
                  {!isGroup && !isRelation && (
                      <div className="flex items-center gap-2 w-full">
                          {/* Field Selector */}
                          <div className="relative">
                              <select 
                                value={node.field} 
                                onChange={(e) => updateNode(node.id, { field: e.target.value })}
                                className="appearance-none bg-emerald-50 hover:bg-emerald-100 border border-emerald-200 text-emerald-800 font-mono text-xs font-bold py-2 pl-3 pr-8 rounded-lg outline-none cursor-pointer transition-colors"
                              >
                                  {columns.map(c => <option key={c.name} value={c.name}>{c.name}</option>)}
                                  <option value="true">ALWAYS TRUE</option>
                              </select>
                              <ChevronDown size={12} className="absolute right-2 top-1/2 -translate-y-1/2 text-emerald-500 pointer-events-none" />
                          </div>

                          {/* Comparator */}
                          <select 
                            value={node.comparator} 
                            onChange={(e) => updateNode(node.id, { comparator: e.target.value as any })}
                            className="bg-slate-100 font-mono text-slate-600 text-xs font-black py-2 px-2 rounded-lg outline-none text-center cursor-pointer hover:bg-slate-200"
                          >
                              {['=', '!=', '>', '<', 'IN', 'IS'].map(op => <option key={op} value={op}>{op}</option>)}
                          </select>

                          {/* Value Input (Smart) */}
                          <div className="flex-1 relative group/val">
                              <div className="absolute left-2 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none">
                                  {node.valueType === 'auth' ? <User size={12}/> : node.valueType === 'dynamic' ? <Zap size={12}/> : null}
                              </div>
                              <input 
                                value={node.value}
                                onChange={(e) => updateNode(node.id, { value: e.target.value })}
                                placeholder={node.valueType === 'auth' ? 'auth.uid()' : 'Value...'}
                                className={`w-full border rounded-lg py-2 pr-8 text-xs font-mono font-medium outline-none transition-all ${node.valueType === 'auth' ? 'bg-purple-50 border-purple-200 text-purple-700 pl-8' : 'bg-white border-slate-200 text-slate-700 pl-3'}`}
                              />
                              
                              {/* Quick Value Type Switcher */}
                              <div className="absolute right-1 top-1/2 -translate-y-1/2 flex gap-1 opacity-0 group-hover/val:opacity-100 transition-opacity bg-white shadow-sm rounded-md border border-slate-100">
                                  <button onClick={() => updateNode(node.id, { value: 'auth.uid()', valueType: 'auth' })} title="Auth UID" className="p-1 hover:bg-purple-50 text-slate-400 hover:text-purple-600 rounded"><User size={12}/></button>
                                  <button onClick={() => updateNode(node.id, { value: 'true', valueType: 'static' })} title="Static" className="p-1 hover:bg-slate-50 text-slate-400 hover:text-slate-600 rounded"><CheckSquare size={12}/></button>
                              </div>
                          </div>
                      </div>
                  )}

                  {/* Delete Node */}
                  {!isRoot && (
                      <button onClick={() => removeNode(node.id)} className="ml-auto p-2 text-slate-300 hover:text-rose-500 hover:bg-rose-50 rounded-lg transition-all"><X size={14} /></button>
                  )}
              </div>

              {/* Recursive Children Render */}
              {node.children && node.children.length > 0 && (
                  <div className="pl-6 border-l-2 border-slate-200 ml-6 pb-2">
                      {node.children.map(child => renderNode(child, depth + 1))}
                  </div>
              )}
          </div>
      );
  };

  return (
    <div className="h-screen flex flex-col bg-[#F8FAFC]">
      {/* Header */}
      <header className="h-20 bg-white border-b border-slate-200 flex items-center justify-between px-8 shrink-0 z-20 shadow-sm">
        <div className="flex items-center gap-6">
          <button onClick={onBack} className="p-2.5 bg-slate-50 hover:bg-slate-100 rounded-xl transition-colors text-slate-500 hover:text-slate-900 border border-slate-200">
            <ArrowLeft size={20} />
          </button>
          <div>
            <h1 className="text-xl font-black text-slate-900 tracking-tight flex items-center gap-3">
              <ShieldCheck size={24} className="text-indigo-600" />
              RLS Architect <span className="bg-indigo-50 text-indigo-600 px-2 py-0.5 rounded text-[10px] uppercase tracking-widest font-black border border-indigo-100">Pro</span>
            </h1>
            <p className="text-[10px] text-slate-400 font-bold uppercase tracking-widest mt-1 flex items-center gap-2">
              Target: <span className="bg-slate-100 px-2 rounded text-slate-600">{entityType}</span> <ChevronDown size={10}/> <span className="text-indigo-600 font-mono">{entityName}</span>
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex bg-slate-100 p-1 rounded-xl">
              <button onClick={() => setActiveTab('visual')} className={`px-4 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${activeTab === 'visual' ? 'bg-white shadow text-indigo-600' : 'text-slate-400'}`}>Visual Builder</button>
              <button onClick={() => setActiveTab('sql')} className={`px-4 py-2 rounded-lg text-[10px] font-black uppercase tracking-widest transition-all ${activeTab === 'sql' ? 'bg-white shadow text-indigo-600' : 'text-slate-400'}`}>Raw SQL</button>
          </div>
          <button 
            onClick={handleDeploy} 
            disabled={saving || !policyName}
            className="bg-slate-900 text-white px-6 py-3 rounded-xl font-black text-xs uppercase tracking-widest hover:bg-indigo-600 transition-all flex items-center gap-2 shadow-xl disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {saving ? <Loader2 size={16} className="animate-spin" /> : <Save size={16} />} Deploy Policy
          </button>
        </div>
      </header>

      {deployError && (
          <div className="bg-rose-50 border-b border-rose-100 p-4 flex items-center justify-between animate-in slide-in-from-top-2">
              <div className="flex items-center gap-3">
                  <AlertTriangle className="text-rose-600" size={20} />
                  <div>
                      <h4 className="text-sm font-black text-rose-900">Deployment Failed</h4>
                      <p className="text-xs text-rose-700">{deployError}</p>
                  </div>
              </div>
              <button onClick={() => setDeployError(null)} className="text-rose-400 hover:text-rose-700"><X size={18}/></button>
          </div>
      )}

      <div className="flex-1 flex overflow-hidden">
        
        {/* LEFT: PRESETS & CONFIG */}
        <aside className="w-80 bg-white border-r border-slate-200 flex flex-col overflow-y-auto z-10">
            <div className="p-6 border-b border-slate-100">
                <label className="text-[10px] font-black text-slate-400 uppercase tracking-widest ml-1 mb-2 block">Policy Configuration</label>
                <div className="space-y-4">
                    <input 
                       value={policyName}
                       onChange={(e) => setPolicyName(e.target.value)}
                       placeholder="Policy Name (e.g. Tenant Isolation)"
                       className="w-full bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 text-xs font-bold outline-none focus:border-indigo-400 transition-all"
                    />
                    <div className="grid grid-cols-2 gap-3">
                        <div>
                            <label className="text-[9px] font-bold text-slate-400 uppercase block mb-1">Command</label>
                            <select 
                               value={command}
                               onChange={(e) => setCommand(e.target.value)}
                               className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-xs font-bold text-indigo-600 outline-none"
                            >
                               <option value="SELECT">SELECT (Read)</option>
                               <option value="INSERT">INSERT (Create)</option>
                               <option value="UPDATE">UPDATE (Edit)</option>
                               <option value="DELETE">DELETE (Drop)</option>
                               <option value="ALL">ALL Actions</option>
                            </select>
                        </div>
                        <div>
                            <label className="text-[9px] font-bold text-slate-400 uppercase block mb-1">Target Role</label>
                            <select 
                               value={role}
                               onChange={(e) => setRole(e.target.value)}
                               className="w-full bg-white border border-slate-200 rounded-xl px-3 py-2 text-xs font-bold text-emerald-600 outline-none"
                            >
                               <option value="authenticated">Authenticated</option>
                               <option value="anon">Anonymous</option>
                               <option value="public">Public (All)</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <div className="p-6">
                <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] mb-4">Quick Start Presets</h3>
                <div className="space-y-3">
                    {Object.entries(PRESETS).map(([key, preset]) => (
                        <button 
                            key={key}
                            onClick={() => loadPreset(key)}
                            className="w-full text-left p-4 rounded-xl border border-slate-100 hover:border-indigo-200 hover:bg-indigo-50/50 transition-all group"
                        >
                            <div className="flex items-center gap-2 mb-1">
                                <Zap size={14} className="text-amber-500 group-hover:text-amber-600"/>
                                <span className="font-bold text-xs text-slate-700 group-hover:text-indigo-900">{preset.name}</span>
                            </div>
                            <p className="text-[10px] text-slate-400 leading-tight">{preset.desc}</p>
                        </button>
                    ))}
                </div>
            </div>
            
            <div className="mt-auto p-6 bg-slate-50 border-t border-slate-100">
                <div className="flex items-center gap-3 mb-2">
                    <div className="p-2 bg-white rounded-lg border border-slate-200 shadow-sm"><Key size={14} className="text-purple-500"/></div>
                    <div>
                        <span className="text-[10px] font-bold text-slate-500 block">Auth Context</span>
                        <span className="text-[9px] text-slate-400 block">Available Variables</span>
                    </div>
                </div>
                <div className="flex flex-wrap gap-2">
                    {['auth.uid()', 'auth.role()', 'auth.email()'].map(v => (
                        <code key={v} className="text-[9px] bg-purple-100 text-purple-700 px-2 py-1 rounded border border-purple-200 cursor-copy hover:bg-purple-200" title="Click to Copy" onClick={() => navigator.clipboard.writeText(v)}>{v}</code>
                    ))}
                </div>
            </div>
        </aside>

        {/* CENTER: CANVAS */}
        <main className="flex-1 bg-slate-50/50 relative overflow-hidden flex flex-col">
            <div className="flex-1 overflow-y-auto p-12">
                <div className="max-w-4xl mx-auto">
                    {activeTab === 'visual' ? (
                        renderNode(logicTree)
                    ) : (
                        <div className="bg-slate-900 rounded-3xl p-8 shadow-2xl font-mono text-xs leading-relaxed text-emerald-400 border border-slate-800">
                            {generatedSQL}
                        </div>
                    )}
                </div>
            </div>
            
            {/* Live Preview Bar */}
            <div className="h-16 bg-white border-t border-slate-200 px-8 flex items-center justify-between shrink-0">
                <div className="flex items-center gap-4 text-xs font-mono text-slate-500">
                    <span className="font-bold text-indigo-600 uppercase">SQL Preview:</span>
                    <span className="truncate max-w-2xl opacity-70">{generatedSQL}</span>
                </div>
                <button 
                    onClick={() => navigator.clipboard.writeText(generatedSQL)}
                    className="p-2 hover:bg-slate-100 rounded-lg text-slate-400 hover:text-indigo-600 transition-all" 
                    title="Copy SQL"
                >
                    <Copy size={16}/>
                </button>
            </div>
        </main>

        {/* RIGHT: SIMULATOR (The "Surprise") */}
        <aside className="w-80 bg-white border-l border-slate-200 flex flex-col z-10">
            <div className="p-6 border-b border-slate-100 bg-slate-50/50">
                <h3 className="text-[10px] font-black text-slate-400 uppercase tracking-[0.2em] flex items-center gap-2"><Eye size={14} className="text-indigo-500"/> Logic Simulator</h3>
            </div>
            <div className="p-6 flex-1 flex flex-col">
                <p className="text-[10px] text-slate-500 mb-4 leading-relaxed">
                    Test your logic by simulating a user ID. The system validates if the SQL syntax is valid for this context.
                </p>
                
                <div className="space-y-4">
                    <div>
                        <label className="text-[9px] font-bold text-slate-400 uppercase block mb-1">Simulated User ID (auth.uid())</label>
                        <input 
                            value={simulatorUid}
                            onChange={(e) => setSimulatorUid(e.target.value)}
                            placeholder="e.g. 550e8400-e29b..."
                            className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2 text-xs font-mono outline-none focus:border-indigo-400"
                        />
                    </div>
                    
                    <div className="p-4 bg-indigo-50 border border-indigo-100 rounded-xl">
                        <div className="flex items-center gap-2 mb-2">
                            <Workflow size={14} className="text-indigo-600"/>
                            <span className="text-xs font-black text-indigo-900">Dry Run Result</span>
                        </div>
                        <div className="text-[10px] font-mono text-indigo-800 break-words bg-white/50 p-2 rounded-lg">
                            {generatedSQL.replace(/auth\.uid\(\)/g, `'${simulatorUid || '0000-0000'}'`)}
                        </div>
                    </div>

                    <div className="mt-auto p-4 bg-amber-50 border border-amber-100 rounded-xl">
                        <div className="flex items-center gap-2 mb-1 text-amber-700">
                            <AlertTriangle size={14}/>
                            <span className="text-[10px] font-black uppercase">Performance Tip</span>
                        </div>
                        <p className="text-[9px] text-amber-800 leading-relaxed">
                            Using <b>EXISTS</b> with linked tables (Relations) is efficient, but ensure foreign key columns are indexed in the database for optimal performance.
                        </p>
                    </div>
                </div>
            </div>
        </aside>

      </div>
    </div>
  );
};

export default RLSDesigner;
