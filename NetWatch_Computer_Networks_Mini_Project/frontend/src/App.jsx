import React, { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowDownToLine, ArrowUpFromLine, BarChart3, Bell, Check,
  ChevronDown, CircleHelp, Clock3, FileSearch, FileUp, Filter, Gauge, Globe2, HardDrive,
  LayoutDashboard, Menu, Network, Pause, Play, Radio, RefreshCw, Search, Server,
  Settings, ShieldAlert, ShieldCheck, SlidersHorizontal, Square, Terminal, Wifi, X
} from 'lucide-react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart,
  ResponsiveContainer, Tooltip, XAxis, YAxis
} from 'recharts'
import { api, downloadFile } from './api'

const COLORS = ['#42d7f5','#8b7cff','#48d6a1','#f6b85e','#f078a7','#7da7ff','#a5b4fc']
const nav = [
  ['Overview',LayoutDashboard],['Live Capture',Radio],['Packet Explorer',FileSearch],
  ['Protocol Analysis',BarChart3],['IP Analysis',Globe2],['Security Alerts',ShieldAlert],
  ['PCAP Analyzer',FileUp],['Reports',ArrowDownToLine]
]
const initialStats = {total_packets:0,total_bytes:0,incoming_bytes:0,outgoing_bytes:0,average_packet_size:0,protocols:[],top_sources:[],top_destinations:[],alerts:[],mode:'idle',running:false}
const fmtBytes = n => n >= 1048576 ? `${(n/1048576).toFixed(2)} MB` : n >= 1024 ? `${(n/1024).toFixed(1)} KB` : `${n || 0} B`
const shortTime = value => { try { return new Date(value).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'}) } catch { return value } }

function App() {
  const [page,setPage] = useState('Overview')
  const [stats,setStats] = useState(initialStats)
  const [packets,setPackets] = useState([])
  const [interfaces,setInterfaces] = useState([])
  const [iface,setIface] = useState('')
  const [mode,setMode] = useState('demo')
  const [filter,setFilter] = useState('all')
  const [search,setSearch] = useState('')
  const [selected,setSelected] = useState(null)
  const [toast,setToast] = useState('')
  const [busy,setBusy] = useState(false)
  const [history,setHistory] = useState([])
  const [mobileOpen,setMobileOpen] = useState(false)
  const [file,setFile] = useState(null)
  const [health,setHealth] = useState('checking')

  const notify = msg => { setToast(msg); setTimeout(()=>setToast(''),3200) }
  const refresh = async () => {
    try {
      const [s,p] = await Promise.all([api.get('/stats'),api.get('/packets?limit=1000')])
      setStats(s.data); setPackets(p.data.packets || [])
      setHistory(old => {
        const next = [...old,{time:new Date().toLocaleTimeString(),packets:s.data.total_packets,bytes:s.data.total_bytes}]
        return next.slice(-24)
      })
      setHealth('online')
    } catch { setHealth('offline') }
  }
  useEffect(() => {
    api.get('/interfaces').then(r=>{setInterfaces(r.data.interfaces || []); if(r.data.interfaces?.length) setIface(r.data.interfaces[0])}).catch(()=>{})
    refresh()
    const id = setInterval(refresh,1500)
    return ()=>clearInterval(id)
  },[])
  const start = async () => {
    setBusy(true)
    try {
      await api.post('/capture/start',{mode,interface:iface})
      notify(mode === 'demo' ? 'Demo capture started' : 'Live capture requested')
      await refresh()
    } catch(e) { notify(e.response?.data?.error || 'Could not start capture. Check backend.') }
    setBusy(false)
  }
  const stop = async () => {
    try { await api.post('/capture/stop'); await refresh(); notify('Capture stopped') }
    catch { notify('Could not stop capture') }
  }
  const upload = async () => {
    if(!file) return notify('Select a PCAP file first')
    const form = new FormData(); form.append('file',file)
    setBusy(true)
    try { const r = await api.post('/pcap/upload',form); await refresh(); notify(`${r.data.packets_loaded} packets loaded from capture file`) }
    catch(e) { notify(e.response?.data?.error || 'PCAP analysis failed') }
    setBusy(false)
  }
  const filtered = useMemo(()=>packets.filter(p=>{
    const proto = filter === 'all' || p.protocol.toLowerCase() === filter
    const q = search.toLowerCase()
    const text = [p.source_ip,p.destination_ip,p.protocol,p.source_port,p.destination_port,p.summary].join(' ').toLowerCase()
    return proto && text.includes(q)
  }),[packets,filter,search])
  const activePage = page
  const menu = (name) => { setPage(name); setMobileOpen(false); setSelected(null) }

  return <div className="app-shell">
    <aside className={`sidebar ${mobileOpen?'open':''}`}>
      <div className="brand"><div className="brand-mark"><Activity size={22}/></div><div><b>netwatch<span>.</span></b><small>NETWORK INTELLIGENCE</small></div><button className="mobile-close icon-btn" onClick={()=>setMobileOpen(false)}><X/></button></div>
      <div className="workspace"><span className="live-dot"/><div><b>Local workstation</b><small>{health==='online'?'API connected':health==='offline'?'API unavailable':'Connecting...'}</small></div><ChevronDown size={15}/></div>
      <div className="nav-label">WORKSPACE</div>
      <nav>{nav.map(([name,Icon])=><button key={name} className={`nav-item ${page===name?'active':''}`} onClick={()=>menu(name)}><Icon size={18}/><span>{name}</span>{name==='Security Alerts' && stats.alerts?.length>0 && <i className="nav-count">{stats.alerts.length}</i>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="help-card"><div className="help-icon"><CircleHelp size={17}/></div><b>Need a hand?</b><p>Explore packet insights and network activity.</p><button onClick={()=>notify('Tip: Start with Demo Mode, then try a permitted live capture.')}>Quick guide <span>↗</span></button></div><div className="side-foot"><span>NETWATCH</span><span>v1.0.0</span></div></div>
    </aside>
    <main className="main">
      <header className="topbar"><div className="top-left"><button className="mobile-menu icon-btn" onClick={()=>setMobileOpen(true)}><Menu/></button><div className="breadcrumb">Workspace <span>/</span> <b>{activePage}</b></div></div><div className="top-actions"><div className={`connection ${health}`}><span/>{health==='online'?'Backend connected':'Backend offline'}</div><button className="icon-btn notification" onClick={()=>menu('Security Alerts')} title="Notifications"><Bell size={18}/>{stats.alerts?.length>0&&<i/>}</button><div className="avatar">NW</div></div></header>
      <div className="content">
        <div className="page-heading"><div><div className="eyebrow">NETWORK OPERATIONS / {page.toUpperCase()}</div><h1>{page==='Overview'?'Network overview':page}</h1><p>{page==='Overview'?'A live view of your network traffic, protocols and security signals.':page==='Live Capture'?'Capture and inspect packets from a selected network interface.':page==='Packet Explorer'?'Search, filter and inspect captured network packets.':`Explore ${page.toLowerCase()} and understand your network activity.`}</p></div><div className="heading-right"><span className={`capture-pill ${stats.running?'capturing':''}`}><i/>{stats.running?'CAPTURING':stats.mode==='pcap'?'PCAP LOADED':'NOT CAPTURING'}</span><button className="btn btn-secondary" onClick={refresh}><RefreshCw size={15}/> Refresh</button></div></div>

        {page==='Overview' && <Overview stats={stats} packets={packets} history={history} onNavigate={menu}/>}
        {page==='Live Capture' && <Capture mode={mode} setMode={setMode} iface={iface} setIface={setIface} interfaces={interfaces} running={stats.running} busy={busy} start={start} stop={stop} packets={packets.slice(0,12)}/>}
        {page==='Packet Explorer' && <Explorer packets={filtered} filter={filter} setFilter={setFilter} search={search} setSearch={setSearch} onSelect={setSelected}/>}
        {page==='Protocol Analysis' && <ProtocolPage stats={stats} packets={packets}/>}
        {page==='IP Analysis' && <IPPage stats={stats}/>}
        {page==='Security Alerts' && <Alerts alerts={stats.alerts||[]}/>}
        {page==='PCAP Analyzer' && <Pcap file={file} setFile={setFile} upload={upload} busy={busy} stats={stats}/>}
        {page==='Reports' && <Reports stats={stats} onDownload={downloadFile} notify={notify}/>}
        {selected && <PacketModal packet={selected} close={()=>setSelected(null)}/>}
        <footer className="footer"><span>NETWATCH <b>•</b> REAL-TIME NETWORK ANALYTICS</span><span>Educational project · Capture only authorized traffic</span></footer>
      </div>
    </main>
    {toast && <div className="toast"><Check size={17}/>{toast}</div>}
  </div>
}

function StatCard({label,value,sub,icon:Icon,accent='blue'}) {
  return <div className="stat-card"><div className={`stat-icon ${accent}`}><Icon size={19}/></div><div className="stat-copy"><span>{label}</span><strong>{value}</strong><small>{sub}</small></div><div className="stat-spark">↗</div></div>
}
function Panel({title,subtitle,action,children,className=''}) {return <section className={`panel ${className}`}><div className="panel-head"><div><h3>{title}</h3>{subtitle&&<p>{subtitle}</p>}</div>{action}</div>{children}</section>}
function Overview({stats,packets,history,onNavigate}) {
  const protocolData=stats.protocols?.length?stats.protocols:[{name:'No data',value:1}]
  const traffic=history.length?history:[{time:'—',packets:0,bytes:0}]
  return <>
    <div className="stat-grid">
      <StatCard label="Total packets" value={(stats.total_packets||0).toLocaleString()} sub="In current session" icon={Network}/>
      <StatCard label="Data transferred" value={fmtBytes(stats.total_bytes)} sub="Captured packet bytes" icon={HardDrive} accent="purple"/>
      <StatCard label="Avg. packet size" value={`${stats.average_packet_size||0} B`} sub="Across captured packets" icon={Gauge} accent="green"/>
      <StatCard label="Security signals" value={stats.alerts?.length||0} sub="Rule-based observations" icon={ShieldAlert} accent="orange"/>
    </div>
    <div className="grid-two overview-charts">
      <Panel title="Traffic activity" subtitle="Packet count over recent refreshes" action={<span className="legend-dot">● Live session</span>}>
        <div className="chart-wrap"><ResponsiveContainer width="100%" height="100%"><AreaChart data={traffic}><defs><linearGradient id="trafficFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#39c9ee" stopOpacity={.28}/><stop offset="95%" stopColor="#39c9ee" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#25344a" strokeDasharray="3 5" vertical={false}/><XAxis dataKey="time" tick={{fill:'#7e91aa',fontSize:10}} axisLine={false} tickLine={false}/><YAxis tick={{fill:'#7e91aa',fontSize:10}} axisLine={false} tickLine={false}/><Tooltip contentStyle={{background:'#101c2d',border:'1px solid #2a3b52',borderRadius:10,color:'#e9f2ff'}}/><Area type="monotone" dataKey="packets" stroke="#43c9ec" strokeWidth={2} fill="url(#trafficFill)"/></AreaChart></ResponsiveContainer></div>
      </Panel>
      <Panel title="Protocol distribution" subtitle="Breakdown of identified packets">
        <div className="donut-layout"><div className="donut"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={protocolData} dataKey="value" nameKey="name" innerRadius={56} outerRadius={82} paddingAngle={3} stroke="none">{protocolData.map((e,i)=><Cell key={e.name} fill={COLORS[i%COLORS.length]}/>)}</Pie><Tooltip contentStyle={{background:'#101c2d',border:'1px solid #2a3b52',borderRadius:10}}/></PieChart></ResponsiveContainer><div className="donut-center"><b>{stats.total_packets||0}</b><small>PACKETS</small></div></div><div className="protocol-legend">{(stats.protocols||[]).slice(0,6).map((p,i)=><div key={p.name}><i style={{background:COLORS[i%COLORS.length]}}/><span>{p.name}</span><b>{p.value}</b></div>)}{!stats.protocols?.length&&<small className="muted">Start a capture to see protocols.</small>}</div></div>
      </Panel>
    </div>
    <div className="grid-two">
      <Panel title="Recent packets" subtitle="Latest captured network events" action={<button className="text-btn" onClick={()=>onNavigate('Packet Explorer')}>View all ↗</button>}>
        <PacketTable packets={packets.slice(0,6)} compact/>
      </Panel>
      <Panel title="Top source addresses" subtitle="Most active packet sources">
        <div className="rank-list">{(stats.top_sources||[]).slice(0,6).map((x,i)=><div className="rank-row" key={x.ip}><span className="rank-num">{String(i+1).padStart(2,'0')}</span><span className="mono">{x.ip}</span><div className="rank-track"><i style={{width:`${Math.max(5,x.packets/(stats.top_sources[0]?.packets||1)*100)}%`}}/></div><b>{x.packets}</b></div>)}{!stats.top_sources?.length&&<div className="empty">No source data yet</div>}</div>
      </Panel>
    </div>
  </>
}
function Capture({mode,setMode,iface,setIface,interfaces,running,busy,start,stop,packets}) {
  return <div className="capture-layout">
    <Panel title="Capture controls" subtitle="Configure a packet capture session" className="capture-control">
      <div className="mode-switch"><button className={mode==='demo'?'selected':''} onClick={()=>setMode('demo')}><Activity size={16}/> Demo mode</button><button className={mode==='live'?'selected':''} onClick={()=>setMode('live')}><Radio size={16}/> Live capture</button></div>
      <label className="field-label">NETWORK INTERFACE</label><select value={iface} onChange={e=>setIface(e.target.value)} disabled={mode==='demo'}><option value="">Default interface</option>{interfaces.map(i=><option key={i}>{i}</option>)}</select>
      <div className="capture-note"><ShieldCheck size={17}/><span>{mode==='demo'?'Demo mode generates clearly labelled sample packet metadata for safe presentation.':'Live mode captures traffic visible to this machine. Administrator/root permissions and Npcap may be required.'}</span></div>
      <div className="capture-actions">{!running?<button className="btn btn-primary full" disabled={busy} onClick={start}><Play size={16} fill="currentColor"/>{busy?'Starting…':'Start capture'}</button>:<button className="btn btn-danger full" onClick={stop}><Square size={15} fill="currentColor"/> Stop capture</button>}</div>
      <div className="capture-status"><span className={running?'pulse':''}/><div><b>{running?'Capture session active':'Capture is stopped'}</b><small>{running?'Packets are being collected and analyzed':'Start a session to inspect network activity'}</small></div></div>
    </Panel>
    <Panel title="Live packet stream" subtitle="Most recent packet metadata" action={<span className="live-label"><i/> LIVE FEED</span>}>
      <PacketTable packets={packets} compact/>
      <div className="stream-foot"><span>Auto-refresh every 1.5 seconds</span><span>{packets.length} recent records</span></div>
    </Panel>
  </div>
}
function Explorer({packets,filter,setFilter,search,setSearch,onSelect}) {
  return <Panel title="Packet explorer" subtitle={`${packets.length} matching records`} action={<div className="table-tools"><span className="filter-label"><Filter size={14}/> FILTERS</span><select value={filter} onChange={e=>setFilter(e.target.value)}><option value="all">All protocols</option>{['tcp','udp','icmp','dns','arp','tls/https','http'].map(x=><option key={x} value={x}>{x.toUpperCase()}</option>)}</select></div>}>
    <div className="search-box"><Search size={16}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search IP address, protocol, port…"/>{search&&<button onClick={()=>setSearch('')}><X size={14}/></button>}</div>
    <PacketTable packets={packets} onSelect={onSelect}/>
  </Panel>
}
function PacketTable({packets,onSelect,compact=false}) {
  return <div className="table-scroll"><table><thead><tr><th>TIME</th><th>SOURCE</th><th>DESTINATION</th><th>PROTOCOL</th><th>SIZE</th>{!compact&&<th>INFO</th>}</tr></thead><tbody>
    {packets.length?packets.map((p,i)=><tr key={`${p.timestamp}-${i}`} onClick={()=>onSelect?.(p)} className={onSelect?'clickable':''}><td className="muted mono">{shortTime(p.timestamp)}</td><td className="mono">{p.source_ip}</td><td className="mono">{p.destination_ip}</td><td><ProtocolBadge value={p.protocol}/></td><td>{p.length} B</td>{!compact&&<td className="muted">{p.summary}</td>}</tr>):<tr><td colSpan={compact?5:6}><div className="empty"><Network size={22}/><b>No packets to display</b><span>Start a capture or load a PCAP file.</span></div></td></tr>}
  </tbody></table></div>
}
function ProtocolBadge({value}) {const cls=(value||'other').toLowerCase().replace('/','-');return <span className={`protocol-badge ${cls}`}>{value}</span>}
function ProtocolPage({stats,packets}) {
  const data=stats.protocols||[]
  return <div className="grid-two"><Panel title="Protocol distribution" subtitle="Captured packets by protocol"><div className="chart-wrap tall"><ResponsiveContainer width="100%" height="100%"><BarChart data={data} layout="vertical" margin={{left:12,right:20}}><CartesianGrid stroke="#25344a" strokeDasharray="3 5" horizontal={false}/><XAxis type="number" tick={{fill:'#8193aa',fontSize:11}} axisLine={false}/><YAxis dataKey="name" type="category" tick={{fill:'#c5d2e2',fontSize:11}} axisLine={false} tickLine={false} width={78}/><Tooltip contentStyle={{background:'#101c2d',border:'1px solid #2a3b52'}}/><Bar dataKey="value" radius={[0,6,6,0]}>{data.map((d,i)=><Cell key={d.name} fill={COLORS[i%COLORS.length]}/>)}</Bar></BarChart></ResponsiveContainer></div></Panel><Panel title="Protocol summary" subtitle="Packet counts and share">{data.map((p,i)=><div className="protocol-row" key={p.name}><div><i style={{background:COLORS[i%COLORS.length]}}/><b>{p.name}</b></div><strong>{p.value.toLocaleString()}</strong><span>{stats.total_packets?((p.value/stats.total_packets)*100).toFixed(1):0}%</span></div>)}{!data.length&&<div className="empty">No protocol data available</div>}</Panel></div>
}
function IPPage({stats}) {
  const sources=stats.top_sources||[], destinations=stats.top_destinations||[]
  const list=(title,items)=><Panel title={title} subtitle="Ranked by packet count">{items.map((x,i)=><div className="ip-row" key={x.ip}><span className="rank-num">{i+1}</span><Globe2 size={16} className="muted"/><span className="mono">{x.ip}</span><b>{x.packets} packets</b></div>)}{!items.length&&<div className="empty">No IP data available</div>}</Panel>
  return <div className="grid-two">{list('Top source IP addresses',sources)}{list('Top destination IP addresses',destinations)}</div>
}
function Alerts({alerts}) {
  return <Panel title="Security observations" subtitle="Rule-based traffic heuristics. These signals are not confirmation of an attack." action={<span className="alert-count">{alerts.length} signals</span>}>
    {alerts.length?alerts.map((a,i)=><div className="alert-row" key={i}><div className={`alert-symbol ${a.severity.toLowerCase()}`}><AlertTriangle size={18}/></div><div className="alert-main"><div><b>{a.category}</b><span className={`severity ${a.severity.toLowerCase()}`}>{a.severity}</span></div><p>{a.reason}</p><small>Source: <code>{a.source_ip}</code> · Observations: {a.count}</small></div></div>):<div className="empty large"><ShieldCheck size={30}/><b>No suspicious patterns observed</b><span>Start a capture to evaluate traffic. Absence of alerts does not guarantee network safety.</span></div>}
  </Panel>
}
function Pcap({file,setFile,upload,busy,stats}) {
  return <div className="grid-two"><Panel title="Offline capture analysis" subtitle="Upload a Wireshark PCAP file for analysis"><label className="upload-zone"><input type="file" accept=".pcap,.pcapng" onChange={e=>setFile(e.target.files?.[0]||null)}/><div className="upload-icon"><FileUp size={26}/></div><b>{file?file.name:'Drop a PCAP file here'}</b><span>{file?`${(file.size/1024/1024).toFixed(2)} MB · Ready to analyze`:'or click to browse · .pcap / .pcapng · max 50 MB'}</span></label><button className="btn btn-primary full" disabled={!file||busy} onClick={upload}><FileSearch size={16}/>{busy?'Analyzing…':'Analyze capture file'}</button><div className="capture-note"><ShieldCheck size={17}/><span>Uploaded files are processed locally by your backend and removed after parsing. Use captures you are authorized to inspect.</span></div></Panel><Panel title="Current analysis" subtitle="Results from the active session"><div className="pcap-metrics"><div><span>Packets parsed</span><b>{stats.total_packets||0}</b></div><div><span>Data volume</span><b>{fmtBytes(stats.total_bytes)}</b></div><div><span>Session mode</span><b className="mode-text">{stats.mode}</b></div></div><p className="muted small-text">Uploading a new capture replaces the current in-memory packet session.</p></Panel></div>
}
function Reports({stats,onDownload,notify}) {
  const act=async kind=>{try{await onDownload(kind);notify(`${kind.toUpperCase()} report downloaded`)}catch{notify('Report export failed. Check backend connection.')}}
  return <div className="grid-two"><Panel title="Export analysis" subtitle="Download the current capture session"><div className="report-card"><div className="report-icon"><FileSearch/></div><div><b>Packet data export</b><p>CSV file containing packet timestamps, IPs, protocols, ports and lengths.</p></div><button className="btn btn-secondary" onClick={()=>act('csv')}>Export CSV <ArrowDownToLine size={15}/></button></div><div className="report-card"><div className="report-icon purple"><BarChart3/></div><div><b>Network summary report</b><p>PDF overview with session metrics, protocol distribution and heuristic alerts.</p></div><button className="btn btn-secondary" onClick={()=>act('pdf')}>Export PDF <ArrowDownToLine size={15}/></button></div></Panel><Panel title="Session summary" subtitle="Current data snapshot"><div className="report-summary"><div><span>Total packets</span><b>{stats.total_packets||0}</b></div><div><span>Total bytes</span><b>{fmtBytes(stats.total_bytes)}</b></div><div><span>Average packet size</span><b>{stats.average_packet_size||0} B</b></div><div><span>Alerts</span><b>{stats.alerts?.length||0}</b></div></div></Panel></div>
}
function PacketModal({packet:p,close}) {
  return <div className="modal-backdrop" onClick={close}><div className="packet-modal" onClick={e=>e.stopPropagation()}><div className="modal-head"><div><span className="eyebrow">PACKET INSPECTION</span><h2>Packet details</h2></div><button className="icon-btn" onClick={close}><X/></button></div><div className="detail-grid">{[['Timestamp',p.timestamp],['Protocol',p.protocol],['Source IP',p.source_ip],['Destination IP',p.destination_ip],['Source port',p.source_port],['Destination port',p.destination_port],['Packet length',`${p.length} bytes`],['Direction',p.direction],['TCP flags',p.tcp_flags],['Source MAC',p.source_mac],['Destination MAC',p.destination_mac]].map(([k,v])=><div key={k}><span>{k}</span><b className="mono">{v??'-'}</b></div>)}</div><div className="detail-summary"><span>PACKET SUMMARY</span><p>{p.summary}</p></div>{p.demo&&<div className="demo-warning">This record is generated demo data, not a live packet.</div>}</div></div>
}
export default App
