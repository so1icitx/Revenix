"use client"

import { API_URL } from '../../lib/api-config'
import { useEffect, useState } from "react"
import { Bell, Plus, Trash2, TestTube, CheckCircle, XCircle, Slack, MessageSquare, Mail, AlertTriangle, Webhook, RefreshCw } from "lucide-react"

interface AlertingWebhook { id: number; name: string; url: string; type: string; enabled: boolean; events: string[]; created_at: string }

const webhookTypes = [
  { id: "slack", name: "Slack", icon: Slack, color: "text-primary" },
  { id: "discord", name: "Discord", icon: MessageSquare, color: "text-accent" },
  { id: "email", name: "Email", icon: Mail, color: "text-primary" },
  { id: "pagerduty", name: "PagerDuty", icon: AlertTriangle, color: "text-safe" },
  { id: "webhook", name: "Webhook", icon: Webhook, color: "text-muted-foreground" },
]

const severityOptions = ["critical", "high", "medium", "low"]
const sevColors: Record<string, string> = { critical: "bg-severity-critical/10 text-severity-critical border-severity-critical/20", high: "bg-severity-high/10 text-severity-high border-severity-high/20", medium: "bg-severity-medium/10 text-severity-medium border-severity-medium/20", low: "bg-severity-low/10 text-severity-low border-severity-low/20" }

export default function AlertingPage() {
  const [webhooks, setWebhooks] = useState<AlertingWebhook[]>([])
  const [showAddModal, setShowAddModal] = useState(false)
  const [testResults, setTestResults] = useState<Record<number, { status: string; success?: boolean }>>({})
  const [loading, setLoading] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [pageError, setPageError] = useState<string | null>(null)
  const [newWebhook, setNewWebhook] = useState({ name: "", url: "", type: "slack", events: ["critical", "high"] })

  const fetchWebhooks = async () => {
    try {
      setPageError(null)
      const r = await fetch(`${API_URL}/alerting/webhooks`)
      if (!r.ok) {
        const text = await r.text()
        throw new Error(text || `HTTP ${r.status}`)
      }
      setWebhooks(await r.json())
    } catch (err: any) {
      setPageError(err?.message || "Failed to load integrations")
    }
  }
  useEffect(() => { fetchWebhooks() }, [])

  const handleAddWebhook = async () => {
    try {
      setFormError(null)
      setLoading(true)
      const payload = {
        ...newWebhook,
        enabled: true,
        headers: {},
      }
      const r = await fetch(`${API_URL}/alerting/webhooks`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      })
      const data = await r.json().catch(() => ({}))
      if (!r.ok || data?.status === "error") {
        throw new Error(data?.detail || data?.message || `Failed to add integration (${r.status})`)
      }
      setShowAddModal(false)
      setNewWebhook({ name: "", url: "", type: "slack", events: ["critical", "high"] })
      await fetchWebhooks()
    } catch (err: any) {
      setFormError(err?.message || "Failed to add integration")
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteWebhook = async (id: number) => { try { await fetch(`${API_URL}/alerting/webhooks/${id}`, { method: "DELETE" }); fetchWebhooks() } catch {} }

  const handleTestWebhook = async (id: number) => {
    setTestResults({ ...testResults, [id]: { status: "testing" } })
    try { const r = await fetch(`${API_URL}/alerting/webhooks/${id}/test`, { method: "POST" }); const d = await r.json(); setTestResults({ ...testResults, [id]: { status: "done", success: d.success } }); setTimeout(() => setTestResults((p) => { const u = { ...p }; delete u[id]; return u }), 3000) } catch { setTestResults({ ...testResults, [id]: { status: "done", success: false } }) }
  }

  const getTypeInfo = (type: string) => webhookTypes.find((t) => t.id === type) || webhookTypes[4]

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Alerting</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Configure notification channels for security events</p>
        </div>
        <button onClick={() => setShowAddModal(true)} className="flex items-center gap-2 px-4 py-2 bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg text-sm font-medium transition-colors">
          <Plus className="w-3.5 h-3.5" /> Add Integration
        </button>
      </div>

      {pageError && (
        <div className="card-surface p-3 border border-danger/30 bg-danger/5 text-danger text-sm">
          {pageError}
        </div>
      )}

      {/* Integration Type Cards */}
      <div className="grid grid-cols-5 gap-3">
        {webhookTypes.map((type) => {
          const count = webhooks.filter((w) => w.type === type.id).length
          return (
            <div key={type.id} className="card-surface p-4 text-center">
              <type.icon className={`w-6 h-6 mx-auto mb-2 ${type.color}`} />
              <p className="text-xs font-medium text-foreground">{type.name}</p>
              <p className="text-[10px] text-muted-foreground mt-0.5">{count} configured</p>
            </div>
          )
        })}
      </div>

      {/* Configured Integrations */}
      <div className="card-surface overflow-hidden">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h3 className="text-sm font-medium text-foreground">Configured Integrations</h3>
          <button onClick={fetchWebhooks} className="p-1.5 hover:bg-muted rounded-lg transition-colors text-muted-foreground hover:text-foreground">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {webhooks.length === 0 ? (
          <div className="py-16 text-center">
            <Bell className="w-8 h-8 text-muted-foreground mx-auto mb-3 opacity-40" />
            <p className="text-sm text-muted-foreground">No integrations configured</p>
            <p className="text-xs text-muted-foreground mt-1">Add Slack, Discord, or a custom webhook to receive alerts</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead><tr className="border-b border-border">
                {["Type", "Name", "URL", "Events", "Status", ""].map((h) => <th key={h} className="px-4 py-3 text-left text-[10px] font-medium text-muted-foreground uppercase tracking-wider">{h}</th>)}
              </tr></thead>
              <tbody>
                {webhooks.map((webhook) => {
                  const typeInfo = getTypeInfo(webhook.type)
                  const events = Array.isArray(webhook.events) ? webhook.events : []
                  return (
                    <tr key={webhook.id} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors">
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <typeInfo.icon className={`w-4 h-4 ${typeInfo.color}`} />
                          <span className="text-xs text-muted-foreground capitalize">{webhook.type}</span>
                        </div>
                      </td>
                      <td className="px-4 py-2.5 text-sm font-medium text-foreground">{webhook.name}</td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground font-mono max-w-[200px] truncate">{webhook.url}</td>
                      <td className="px-4 py-2.5">
                        <div className="flex gap-1 flex-wrap">
                          {events.map((event) => (
                            <span key={event} className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${sevColors[event] || "bg-muted text-muted-foreground border-border"}`}>{event}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-2.5">
                        {webhook.enabled
                          ? <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-safe/10 text-safe border border-safe/20">Active</span>
                          : <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[11px] font-medium bg-muted text-muted-foreground border border-border">Disabled</span>
                        }
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-1.5">
                          <button onClick={() => handleTestWebhook(webhook.id)} disabled={testResults[webhook.id]?.status === "testing"} className="px-2.5 py-1 bg-muted hover:bg-border-hover text-muted-foreground hover:text-foreground text-[11px] rounded-lg transition-colors flex items-center gap-1">
                            {testResults[webhook.id]?.status === "testing" ? <><RefreshCw className="w-3 h-3 animate-spin" /> Testing...</>
                            : testResults[webhook.id]?.status === "done" ? (testResults[webhook.id]?.success ? <><CheckCircle className="w-3 h-3 text-safe" /> Sent</> : <><XCircle className="w-3 h-3 text-danger" /> Failed</>)
                            : <><TestTube className="w-3 h-3" /> Test</>}
                          </button>
                          <button onClick={() => handleDeleteWebhook(webhook.id)} className="p-1.5 bg-muted hover:bg-danger/10 text-muted-foreground hover:text-danger rounded-lg transition-colors">
                            <Trash2 className="w-3 h-3" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add Modal */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setShowAddModal(false)}>
          <div className="bg-card border border-border rounded-xl max-w-lg w-full p-6 animate-fadeIn" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-foreground mb-5 flex items-center gap-2"><Bell className="w-4 h-4 text-primary" /> Add Integration</h2>
            {formError && (
              <div className="mb-4 px-3 py-2 rounded-lg bg-danger/10 border border-danger/30 text-danger text-xs">
                {formError}
              </div>
            )}
            <div className="space-y-4">
              <div>
                <label className="block text-[10px] text-muted-foreground mb-2 uppercase tracking-wider">Type</label>
                <div className="grid grid-cols-5 gap-2">
                  {webhookTypes.map((type) => (
                    <button key={type.id} onClick={() => setNewWebhook({ ...newWebhook, type: type.id })} className={`p-3 rounded-lg border transition-all flex flex-col items-center gap-1.5 ${newWebhook.type === type.id ? "bg-primary/10 border-primary/30" : "bg-muted border-border hover:border-border-hover"}`}>
                      <type.icon className={`w-4 h-4 ${type.color}`} />
                      <span className="text-[10px] text-foreground">{type.name}</span>
                    </button>
                  ))}
                </div>
              </div>
              <div>
                <label className="block text-[10px] text-muted-foreground mb-1.5 uppercase tracking-wider">Name</label>
                <input type="text" value={newWebhook.name} onChange={(e) => setNewWebhook({ ...newWebhook, name: e.target.value })} placeholder="e.g., Security Team Slack" className="w-full px-3 py-2 bg-muted border border-border rounded-lg text-sm text-foreground focus:outline-none focus:border-primary transition-colors" />
              </div>
              <div>
                <label className="block text-[10px] text-muted-foreground mb-1.5 uppercase tracking-wider">Webhook URL</label>
                <input type="url" value={newWebhook.url} onChange={(e) => setNewWebhook({ ...newWebhook, url: e.target.value })} placeholder="https://hooks.slack.com/..." className="w-full px-3 py-2 bg-muted border border-border rounded-lg text-sm text-foreground font-mono focus:outline-none focus:border-primary transition-colors" />
              </div>
              <div>
                <label className="block text-[10px] text-muted-foreground mb-2 uppercase tracking-wider">Alert Severity</label>
                <div className="flex gap-2">
                  {severityOptions.map((sev) => (
                    <button key={sev} onClick={() => { const events = newWebhook.events.includes(sev) ? newWebhook.events.filter((e) => e !== sev) : [...newWebhook.events, sev]; setNewWebhook({ ...newWebhook, events }) }}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all capitalize ${newWebhook.events.includes(sev) ? sevColors[sev] : "bg-muted border-border text-muted-foreground"}`}
                    >{sev}</button>
                  ))}
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => setShowAddModal(false)} className="px-4 py-2 bg-muted hover:bg-border-hover text-foreground text-sm rounded-lg transition-colors font-medium">Cancel</button>
              <button onClick={handleAddWebhook} disabled={loading || !newWebhook.name || !newWebhook.url} className="px-4 py-2 bg-primary hover:bg-primary/90 text-primary-foreground text-sm rounded-lg font-medium transition-colors disabled:opacity-50">
                {loading ? "Adding..." : "Add"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
