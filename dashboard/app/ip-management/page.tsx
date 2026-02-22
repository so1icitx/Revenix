"use client"

import { API_URL } from '../../lib/api-config'
import { getAuthToken } from '../../lib/auth'
import { useEffect, useState } from "react"
import { Shield, ShieldOff, Plus, Trash2, Search, RefreshCw, CheckCircle, XCircle, Clock, Globe, Upload } from "lucide-react"

interface TrustedIP { ip: string; confidence: number; permanent: boolean; auto_added: boolean; added_by?: string; notes?: string; good_flows: number; last_seen?: string }
interface BlockedIP { ip: string; block_reason: string; confidence: number; permanent: boolean; manual_override: boolean; hours_remaining?: number; added_by?: string; notes?: string; blocked_at?: string }
interface FirewallLog { action: string; ip: string; success: boolean; error?: string; execution_time_ms: number; timestamp: string }
interface IPGeoData { ip: string; country?: string; country_code?: string; city?: string; isp?: string; org?: string; asn?: string; asn_name?: string; is_private?: boolean; error?: string }

type Tab = "whitelist" | "blocklist" | "firewall"

function Badge({ variant, children }: { variant: "safe" | "danger" | "warning" | "info" | "muted"; children: React.ReactNode }) {
  const styles = {
    safe: "bg-safe/10 text-safe border-safe/20",
    danger: "bg-danger/10 text-danger border-danger/20",
    warning: "bg-warning/10 text-warning border-warning/20",
    info: "bg-primary/10 text-primary border-primary/20",
    muted: "bg-muted text-muted-foreground border-border",
  }
  return <span className={`inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium border ${styles[variant]}`}>{children}</span>
}

export default function IPManagementPage() {
  const [trustedIPs, setTrustedIPs] = useState<TrustedIP[]>([])
  const [blockedIPs, setBlockedIPs] = useState<BlockedIP[]>([])
  const [firewallLogs, setFirewallLogs] = useState<FirewallLog[]>([])
  const [firewallStats, setFirewallStats] = useState<any>(null)
  const [activeTab, setActiveTab] = useState<Tab>("whitelist")
  const [newIP, setNewIP] = useState("")
  const [notes, setNotes] = useState("")
  const [isPermanent, setIsPermanent] = useState(true)
  const [blockDuration, setBlockDuration] = useState(24)
  const [loading, setLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState("")
  const [bulkMode, setBulkMode] = useState(false)
  const [selectedIPs, setSelectedIPs] = useState<Set<string>>(new Set())
  const [bulkIPs, setBulkIPs] = useState("")
  const [showBulkModal, setShowBulkModal] = useState(false)
  const [geoData, setGeoData] = useState<Record<string, IPGeoData>>({})
  const [loadingGeo, setLoadingGeo] = useState<Set<string>>(new Set())
  const [verificationResult, setVerificationResult] = useState<any>(null)
  const [verifying, setVerifying] = useState(false)

  const authFetch = async (url: string, init: RequestInit = {}) => {
    const headers = new Headers(init.headers ?? {})
    const token = getAuthToken()
    if (token && !headers.has("Authorization")) {
      headers.set("Authorization", `Bearer ${token}`)
    }
    return fetch(url, { ...init, headers })
  }

  const fetchData = async () => {
    try {
      const [trustedRes, blockedRes, firewallRes] = await Promise.all([
        authFetch(`${API_URL}/self-healing/trusted-ips`),
        authFetch(`${API_URL}/self-healing/blocked-ips`),
        authFetch(`${API_URL}/self-healing/firewall-status`),
      ])
      if (trustedRes.ok) setTrustedIPs(await trustedRes.json())
      if (blockedRes.ok) setBlockedIPs(await blockedRes.json())
      if (firewallRes.ok) { const data = await firewallRes.json(); setFirewallLogs(data.recent_logs || []); setFirewallStats(data.stats) }
    } catch (error) { console.error("[IPManagement] Fetch error:", error) }
  }

  useEffect(() => { fetchData(); const interval = setInterval(fetchData, 10000); return () => clearInterval(interval) }, [])

  const lookupGeo = async (ip: string) => {
    if (geoData[ip] || loadingGeo.has(ip)) return
    setLoadingGeo((prev) => new Set(prev).add(ip))
    try { const r = await authFetch(`${API_URL}/ip/lookup/${ip}`); if (r.ok) { const d = await r.json(); setGeoData((p) => ({ ...p, [ip]: d })) } } catch {} finally { setLoadingGeo((prev) => { const u = new Set(prev); u.delete(ip); return u }) }
  }

  const verifyFirewall = async () => {
    setVerifying(true)
    try { const r = await authFetch(`${API_URL}/firewall/verify`, { method: "POST" }); if (r.ok) setVerificationResult(await r.json()) } catch {} finally { setVerifying(false) }
  }

  const handleBulkOperation = async (action: "whitelist" | "block" | "unblock") => {
    const ips = bulkMode ? Array.from(selectedIPs) : bulkIPs.split(/[\n,]/).map((ip) => ip.trim()).filter(Boolean)
    if (ips.length === 0) return
    setLoading(true)
    try {
      const r = await authFetch(`${API_URL}/self-healing/bulk-operation`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ips, action, permanent: isPermanent, notes: notes || `Bulk ${action}`, added_by: "admin", expires_hours: blockDuration }) })
      if (r.ok) { setSelectedIPs(new Set()); setBulkIPs(""); setShowBulkModal(false); setBulkMode(false); fetchData() }
    } catch {} finally { setLoading(false) }
  }

  const handleAddWhitelist = async () => {
    if (!newIP.trim()) return; setLoading(true)
    try {
      const endpoint = isPermanent ? `${API_URL}/self-healing/trusted-ips/permanent` : `${API_URL}/self-healing/trusted-ips/add`
      const r = await authFetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip: newIP.trim(), notes: notes.trim() || undefined, added_by: "admin", confidence: isPermanent ? 1.0 : 0.8, auto_added: false, metadata: {} }) })
      if (r.ok) { setNewIP(""); setNotes(""); fetchData() }
    } catch {} finally { setLoading(false) }
  }

  const handleAddBlock = async () => {
    if (!newIP.trim()) return; setLoading(true)
    try {
      const endpoint = isPermanent ? `${API_URL}/self-healing/blocked-ips/permanent` : `${API_URL}/self-healing/blocked-ips/add`
      const body = isPermanent
        ? { ip: newIP.trim(), notes: notes.trim() || "Manually blocked", added_by: "admin" }
        : { ip: newIP.trim(), block_reason: notes.trim() || "Manually blocked", confidence: 1.0, expires_hours: blockDuration, threat_category: "MANUAL_BLOCK", manual_override: true }
      const r = await authFetch(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
      if (r.ok) { setNewIP(""); setNotes(""); fetchData() }
    } catch {} finally { setLoading(false) }
  }

  const handleRemoveWhitelist = async (ip: string) => { try { const r = await authFetch(`${API_URL}/self-healing/trusted-ips/${encodeURIComponent(ip)}`, { method: "DELETE" }); if (r.ok) fetchData(); else console.error("[IPManagement] remove whitelist failed", r.status) } catch {} }
  const handleUnblock = async (ip: string) => { try { const r = await authFetch(`${API_URL}/self-healing/blocked-ips/${encodeURIComponent(ip)}/unblock`, { method: "DELETE" }); if (r.ok) fetchData(); else console.error("[IPManagement] unblock failed", r.status) } catch {} }
  const toggleSelection = (ip: string) => { setSelectedIPs((prev) => { const u = new Set(prev); u.has(ip) ? u.delete(ip) : u.add(ip); return u }) }

  const filteredTrusted = trustedIPs.filter((ip) => ip.ip.includes(searchQuery) || ip.notes?.toLowerCase().includes(searchQuery.toLowerCase()))
  const filteredBlocked = blockedIPs.filter((ip) => ip.ip.includes(searchQuery) || ip.block_reason?.toLowerCase().includes(searchQuery.toLowerCase()))

  const GeoCell = ({ ip }: { ip: string }) => {
    if (geoData[ip]) {
      return geoData[ip].is_private
        ? <span className="text-muted-foreground text-xs">Private</span>
        : <span className="text-xs text-muted-foreground">{geoData[ip].country_code} {geoData[ip].isp?.slice(0, 20)}</span>
    }
    return (
      <button onClick={() => lookupGeo(ip)} disabled={loadingGeo.has(ip)} className="text-[11px] text-muted-foreground hover:text-primary flex items-center gap-1 transition-colors">
        {loadingGeo.has(ip) ? <RefreshCw className="w-3 h-3 animate-spin" /> : <><Globe className="w-3 h-3" /> Lookup</>}
      </button>
    )
  }

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">IP Management</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Manage trusted IPs, blocklists, and firewall synchronization</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => setShowBulkModal(true)} className="flex items-center gap-2 px-3 py-2 bg-card text-muted-foreground border border-border hover:border-border-hover rounded-lg text-xs font-medium transition-colors">
            <Upload className="w-3.5 h-3.5" /> Bulk Import
          </button>
          <button onClick={() => setBulkMode(!bulkMode)} className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all ${bulkMode ? "bg-primary text-primary-foreground" : "bg-card text-muted-foreground border border-border hover:border-border-hover"}`}>
            {bulkMode ? "Exit Bulk" : "Bulk Select"}
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: "Whitelisted", value: trustedIPs.length, sub: `${trustedIPs.filter((ip) => ip.permanent).length} permanent`, color: "text-safe" },
          { label: "Blocked", value: blockedIPs.length, sub: `${blockedIPs.filter((ip) => ip.permanent).length} permanent`, color: "text-danger" },
          { label: "Syncs (1h)", value: firewallStats?.successful_last_hour || 0, sub: `${firewallStats?.failed_last_hour || 0} failed`, color: "text-primary" },
          { label: "Avg Sync", value: `${firewallStats?.avg_execution_time_ms || 0}ms`, sub: "", color: "text-warning" },
          { label: "Status", value: verificationResult ? `${verificationResult.verification_rate?.toFixed(0)}%` : "--", sub: verificationResult ? `${verificationResult.missing_blocks?.length || 0} missing` : "", color: "text-foreground", action: !verificationResult ? () => verifyFirewall() : undefined, actionLabel: "Verify" },
        ].map((s) => (
          <div key={s.label} className="card-surface p-4">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{s.label}</p>
            {s.action ? (
              <button onClick={s.action} disabled={verifying} className="text-sm text-primary hover:text-primary/80 font-medium mt-1 transition-colors">
                {verifying ? "Verifying..." : s.actionLabel}
              </button>
            ) : (
              <>
                <p className={`text-xl font-semibold mt-1 ${s.color}`}>{s.value}</p>
                {s.sub && <p className="text-[10px] text-muted-foreground mt-0.5">{s.sub}</p>}
              </>
            )}
          </div>
        ))}
      </div>

      {/* Bulk selection bar */}
      {bulkMode && selectedIPs.size > 0 && (
        <div className="card-surface p-3 flex items-center justify-between animate-fadeIn">
          <p className="text-sm text-foreground"><span className="font-semibold text-primary">{selectedIPs.size}</span> IPs selected</p>
          <div className="flex gap-2">
            <button onClick={() => handleBulkOperation("whitelist")} className="px-3 py-1.5 bg-safe/10 text-safe border border-safe/20 rounded-lg text-xs font-medium hover:bg-safe/20 transition-colors">Whitelist</button>
            <button onClick={() => handleBulkOperation("block")} className="px-3 py-1.5 bg-danger/10 text-danger border border-danger/20 rounded-lg text-xs font-medium hover:bg-danger/20 transition-colors">Block</button>
            <button onClick={() => handleBulkOperation("unblock")} className="px-3 py-1.5 bg-muted text-muted-foreground border border-border rounded-lg text-xs font-medium hover:bg-border-hover transition-colors">Unblock</button>
            <button onClick={() => setSelectedIPs(new Set())} className="px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">Clear</button>
          </div>
        </div>
      )}

      {/* Tabs + Search */}
      <div className="flex items-center gap-4">
        <div className="flex gap-1 p-1 bg-muted rounded-xl">
          {(["whitelist", "blocklist", "firewall"] as const).map((tab) => (
            <button key={tab} onClick={() => setActiveTab(tab)} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${activeTab === tab ? "bg-card text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"}`}>
              {tab === "whitelist" && <Shield className="w-3 h-3" />}
              {tab === "blocklist" && <ShieldOff className="w-3 h-3" />}
              {tab === "firewall" && <RefreshCw className="w-3 h-3" />}
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
          <input type="text" value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} placeholder="Search IPs..." className="w-full pl-9 pr-3 py-2 bg-muted border border-border rounded-lg text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary transition-colors" />
        </div>
      </div>

      {/* Add IP Form */}
      {activeTab !== "firewall" && (
        <div className="card-surface p-4 animate-fadeIn">
          <div className="flex flex-wrap gap-3 items-end">
            <div className="flex-1 min-w-[180px]">
              <label className="block text-[10px] text-muted-foreground mb-1 uppercase tracking-wider">IP Address</label>
              <input type="text" value={newIP} onChange={(e) => setNewIP(e.target.value)} placeholder="192.168.1.100" className="w-full px-3 py-2 bg-muted border border-border rounded-lg text-sm text-foreground focus:outline-none focus:border-primary transition-colors" />
            </div>
            <div className="flex-1 min-w-[180px]">
              <label className="block text-[10px] text-muted-foreground mb-1 uppercase tracking-wider">Notes</label>
              <input type="text" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Reason..." className="w-full px-3 py-2 bg-muted border border-border rounded-lg text-sm text-foreground focus:outline-none focus:border-primary transition-colors" />
            </div>
            <label className="flex items-center gap-2 cursor-pointer">
              <button onClick={() => setIsPermanent(!isPermanent)} className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${isPermanent ? "bg-primary" : "bg-muted"}`}>
                <span className={`inline-block h-3.5 w-3.5 rounded-full bg-foreground transition-transform ${isPermanent ? "translate-x-4.5" : "translate-x-0.5"}`} />
              </button>
              <span className="text-xs text-muted-foreground">Permanent</span>
            </label>
            {!isPermanent && activeTab === "blocklist" && (
              <select value={blockDuration} onChange={(e) => setBlockDuration(Number(e.target.value))} className="h-9 px-3 bg-muted border border-border rounded-lg text-sm text-foreground focus:outline-none focus:border-primary appearance-none cursor-pointer">
                <option value={1}>1h</option><option value={6}>6h</option><option value={24}>24h</option><option value={72}>3d</option><option value={168}>1w</option>
              </select>
            )}
            <button onClick={activeTab === "whitelist" ? handleAddWhitelist : handleAddBlock} disabled={loading || !newIP.trim()} className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium transition-all disabled:opacity-50 ${activeTab === "whitelist" ? "bg-safe text-background hover:bg-safe/90" : "bg-danger text-foreground hover:bg-danger/90"}`}>
              <Plus className="w-3.5 h-3.5" /> {loading ? "Adding..." : "Add"}
            </button>
          </div>
        </div>
      )}

      {/* Tables */}
      {activeTab === "whitelist" && (
        <div className="card-surface overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b border-border">
                {bulkMode && <th className="px-4 py-3 w-10"></th>}
                {["IP Address", "Location", "Status", "Confidence", "Notes", ""].map((h) => <th key={h} className="px-4 py-3 text-left text-[10px] font-medium text-muted-foreground uppercase tracking-wider">{h}</th>)}
              </tr></thead>
              <tbody>
                {filteredTrusted.length === 0 ? (
                  <tr><td colSpan={bulkMode ? 7 : 6} className="px-4 py-10 text-center text-muted-foreground text-sm">No whitelisted IPs</td></tr>
                ) : filteredTrusted.map((ip) => (
                  <tr key={ip.ip} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors">
                    {bulkMode && <td className="px-4 py-2.5"><input type="checkbox" checked={selectedIPs.has(ip.ip)} onChange={() => toggleSelection(ip.ip)} className="w-3.5 h-3.5 rounded border-border bg-muted text-primary accent-primary" /></td>}
                    <td className="px-4 py-2.5 font-mono text-sm text-primary">{ip.ip}</td>
                    <td className="px-4 py-2.5"><GeoCell ip={ip.ip} /></td>
                    <td className="px-4 py-2.5">{ip.permanent ? <Badge variant="safe">Permanent</Badge> : ip.auto_added ? <Badge variant="info">Auto</Badge> : <Badge variant="muted">Manual</Badge>}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground font-mono">{(ip.confidence * 100).toFixed(0)}%</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground max-w-[200px] truncate">{ip.notes || "-"}</td>
                    <td className="px-4 py-2.5">
                      <button onClick={() => handleRemoveWhitelist(ip.ip)} className="px-2.5 py-1 bg-muted hover:bg-danger/10 text-muted-foreground hover:text-danger text-[11px] rounded-lg transition-colors flex items-center gap-1">
                        <Trash2 className="w-3 h-3" /> Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === "blocklist" && (
        <div className="card-surface overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b border-border">
                {bulkMode && <th className="px-4 py-3 w-10"></th>}
                {["IP Address", "Location", "Status", "Reason", "Expires", ""].map((h) => <th key={h} className="px-4 py-3 text-left text-[10px] font-medium text-muted-foreground uppercase tracking-wider">{h}</th>)}
              </tr></thead>
              <tbody>
                {filteredBlocked.length === 0 ? (
                  <tr><td colSpan={bulkMode ? 7 : 6} className="px-4 py-10 text-center text-muted-foreground text-sm">No blocked IPs</td></tr>
                ) : filteredBlocked.map((ip) => (
                  <tr key={ip.ip} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors">
                    {bulkMode && <td className="px-4 py-2.5"><input type="checkbox" checked={selectedIPs.has(ip.ip)} onChange={() => toggleSelection(ip.ip)} className="w-3.5 h-3.5 rounded border-border bg-muted text-primary accent-primary" /></td>}
                    <td className="px-4 py-2.5 font-mono text-sm text-danger">{ip.ip}</td>
                    <td className="px-4 py-2.5"><GeoCell ip={ip.ip} /></td>
                    <td className="px-4 py-2.5">{ip.permanent ? <Badge variant="danger">Permanent</Badge> : ip.manual_override ? <Badge variant="warning">Manual</Badge> : <Badge variant="info">Auto</Badge>}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground max-w-[200px] truncate">{ip.block_reason}</td>
                    <td className="px-4 py-2.5 text-xs">
                      {ip.permanent ? <span className="text-danger">Never</span> : ip.hours_remaining ? <span className="text-muted-foreground flex items-center gap-1"><Clock className="w-3 h-3" />{ip.hours_remaining.toFixed(1)}h</span> : <span className="text-muted-foreground">Expired</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      <button onClick={() => handleUnblock(ip.ip)} className="px-2.5 py-1 bg-muted hover:bg-safe/10 text-muted-foreground hover:text-safe text-[11px] rounded-lg transition-colors flex items-center gap-1">
                        <CheckCircle className="w-3 h-3" /> Unblock
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === "firewall" && (
        <div className="card-surface overflow-hidden">
          <div className="px-4 py-3 border-b border-border flex justify-between items-center">
            <h3 className="text-sm font-medium text-foreground">Recent Sync Activity</h3>
            <div className="flex gap-2">
              <button onClick={verifyFirewall} disabled={verifying} className="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 text-primary border border-primary/20 rounded-lg text-[11px] font-medium hover:bg-primary/20 transition-colors">
                {verifying ? <RefreshCw className="w-3 h-3 animate-spin" /> : <CheckCircle className="w-3 h-3" />} Verify
              </button>
              <button onClick={fetchData} className="flex items-center gap-1.5 px-3 py-1.5 bg-muted text-muted-foreground border border-border rounded-lg text-[11px] font-medium hover:text-foreground transition-colors">
                <RefreshCw className="w-3 h-3" /> Refresh
              </button>
            </div>
          </div>
          {verificationResult && (
            <div className="px-4 py-3 border-b border-border bg-muted/30">
              <div className="grid grid-cols-4 gap-4 text-xs">
                <div><p className="text-muted-foreground">Platform</p><p className="text-foreground font-medium mt-0.5">{verificationResult.platform}</p></div>
                <div><p className="text-muted-foreground">Total Blocked</p><p className="text-foreground font-medium mt-0.5">{verificationResult.total_blocked}</p></div>
                <div><p className="text-muted-foreground">Verified</p><p className="text-safe font-medium mt-0.5">{verificationResult.verified_blocks?.length || 0}</p></div>
                <div><p className="text-muted-foreground">Missing</p><p className="text-danger font-medium mt-0.5">{verificationResult.missing_blocks?.length || 0}</p></div>
              </div>
              {verificationResult.errors?.length > 0 && <div className="mt-2 p-2 bg-danger/10 border border-danger/20 rounded-lg text-[11px] text-danger">{verificationResult.errors.join(", ")}</div>}
            </div>
          )}
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b border-border">
                {["Status", "Action", "IP", "Time", "Error", "Timestamp"].map((h) => <th key={h} className="px-4 py-3 text-left text-[10px] font-medium text-muted-foreground uppercase tracking-wider">{h}</th>)}
              </tr></thead>
              <tbody>
                {firewallLogs.length === 0 ? (
                  <tr><td colSpan={6} className="px-4 py-10 text-center text-muted-foreground text-sm">No firewall logs</td></tr>
                ) : firewallLogs.map((log, idx) => (
                  <tr key={idx} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors">
                    <td className="px-4 py-2.5">{log.success ? <CheckCircle className="w-3.5 h-3.5 text-safe" /> : <XCircle className="w-3.5 h-3.5 text-danger" />}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{log.action}</td>
                    <td className="px-4 py-2.5 font-mono text-xs text-primary">{log.ip}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground font-mono">{log.execution_time_ms}ms</td>
                    <td className="px-4 py-2.5 text-xs text-danger max-w-[200px] truncate">{log.error || "-"}</td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">{log.timestamp}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Bulk Modal */}
      {showBulkModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setShowBulkModal(false)}>
          <div className="bg-card border border-border rounded-xl max-w-lg w-full p-6 animate-fadeIn" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-foreground mb-5 flex items-center gap-2"><Upload className="w-4 h-4 text-primary" /> Bulk Import</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-[10px] text-muted-foreground mb-1.5 uppercase tracking-wider">IPs (one per line or comma-separated)</label>
                <textarea value={bulkIPs} onChange={(e) => setBulkIPs(e.target.value)} placeholder={"192.168.1.100\n10.0.0.1\n172.16.0.1"} rows={5} className="w-full px-3 py-2 bg-muted border border-border rounded-lg font-mono text-sm text-foreground focus:outline-none focus:border-primary resize-none transition-colors" />
              </div>
              <div>
                <label className="block text-[10px] text-muted-foreground mb-1.5 uppercase tracking-wider">Notes</label>
                <input type="text" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Reason..." className="w-full px-3 py-2 bg-muted border border-border rounded-lg text-sm text-foreground focus:outline-none focus:border-primary transition-colors" />
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => setShowBulkModal(false)} className="px-4 py-2 bg-muted hover:bg-border-hover text-foreground text-sm rounded-lg transition-colors font-medium">Cancel</button>
              <button onClick={() => handleBulkOperation("whitelist")} disabled={loading || !bulkIPs.trim()} className="px-4 py-2 bg-safe text-background text-sm rounded-lg font-medium transition-colors hover:bg-safe/90 disabled:opacity-50">Whitelist</button>
              <button onClick={() => handleBulkOperation("block")} disabled={loading || !bulkIPs.trim()} className="px-4 py-2 bg-danger text-foreground text-sm rounded-lg font-medium transition-colors hover:bg-danger/90 disabled:opacity-50">Block</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
