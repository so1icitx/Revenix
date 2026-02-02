"use client"

import { API_URL } from '../../lib/api-config'
import { useState, useEffect } from "react"
import { Save, CheckCircle, Brain, Shield, Database, Activity, Globe, AlertCircle } from "lucide-react"
import { TIMEZONE_OPTIONS, getTimezoneValue, setTimezone, type TimezoneOption } from "../../lib/time"

interface ConfigValue {
  value: number | boolean | string
  description?: string
  updated_at?: string
}
interface Config { [key: string]: ConfigValue | number | boolean | string }

type TabId = "ml" | "firewall" | "system" | "retention"

const tabs: { id: TabId; label: string; icon: typeof Brain }[] = [
  { id: "ml", label: "Machine Learning", icon: Brain },
  { id: "firewall", label: "Firewall", icon: Shield },
  { id: "retention", label: "Data Retention", icon: Database },
  { id: "system", label: "System", icon: Activity },
]

function SettingRow({ label, description, children }: { label: string; description: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-8 py-5 border-b border-border last:border-0">
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-foreground">{label}</p>
        <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{description}</p>
      </div>
      <div className="flex-shrink-0 w-48">{children}</div>
    </div>
  )
}

function NumberInput({ value, onChange, min, max, step }: { value: number; onChange: (v: number) => void; min: number; max: number; step?: number }) {
  return (
    <div className="flex items-center gap-2">
      <button onClick={() => onChange(Math.max(min, value - (step || 1)))} className="w-8 h-8 rounded-lg bg-muted hover:bg-border-hover text-foreground flex items-center justify-center transition-colors text-sm font-medium">-</button>
      <input
        type="text"
        value={step && step < 1 ? value.toFixed(2) : value}
        onChange={(e) => { const n = parseFloat(e.target.value); if (!isNaN(n) && n >= min && n <= max) onChange(n) }}
        className="flex-1 h-8 bg-muted border border-border rounded-lg text-center text-sm text-foreground font-mono focus:outline-none focus:border-primary transition-colors"
      />
      <button onClick={() => onChange(Math.min(max, value + (step || 1)))} className="w-8 h-8 rounded-lg bg-muted hover:bg-border-hover text-foreground flex items-center justify-center transition-colors text-sm font-medium">+</button>
    </div>
  )
}

function SelectInput({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: { value: string; label: string }[] }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full h-9 px-3 bg-muted border border-border rounded-lg text-sm text-foreground focus:outline-none focus:border-primary transition-colors appearance-none cursor-pointer"
    >
      {options.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
    </select>
  )
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${checked ? "bg-primary" : "bg-muted"}`}
    >
      <span className={`inline-block h-4 w-4 rounded-full bg-foreground transition-transform ${checked ? "translate-x-6" : "translate-x-1"}`} />
    </button>
  )
}

export default function SettingsPage() {
  const [saveStatus, setSaveStatus] = useState<"idle" | "saving" | "success" | "error">("idle")
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<TabId>("ml")

  const [mlSettings, setMLSettings] = useState({
    trainingThreshold: 500, alertThreshold: 0.85, blockThreshold: 0.95,
    autoencoderRetrainDays: 7, autoencoderMinFlows: 100, ensembleVotingThreshold: 0.7,
  })
  const [firewallSettings, setFirewallSettings] = useState({
    autoBlockEnabled: true, blockDurationMinutes: 60, firewallSyncInterval: 30, maxConcurrentBlocks: 1000,
  })
  const [systemSettings, setSystemSettings] = useState({
    learningPhase: "active", pollingInterval: 5, logLevel: "INFO", timezone: "local" as TimezoneOption,
  })
  const [retentionSettings, setRetentionSettings] = useState({
    maxFlowsStored: 10000, alertRetentionDays: 30, cleanupIntervalHours: 24,
  })

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const response = await fetch(`${API_URL}/self-healing/model-config`, { cache: "no-store" })
        if (!response.ok) throw new Error("Failed to load settings")
        const config: Config = await response.json()
        const getValue = (key: string, fallback: number | boolean | string) => {
          if (!(key in config)) return fallback
          const entry = config[key]
          if (entry && typeof entry === "object" && "value" in entry) return entry.value
          return entry ?? fallback
        }
        setMLSettings({
          trainingThreshold: Number(getValue("training_threshold", 500)),
          alertThreshold: Number(getValue("alert_threshold", 0.85)),
          blockThreshold: Number(getValue("auto_block_threshold", 0.95)),
          autoencoderRetrainDays: Number(getValue("autoencoder_retrain_days", 7)),
          autoencoderMinFlows: Number(getValue("autoencoder_min_flows", 100)),
          ensembleVotingThreshold: Number(getValue("ensemble_voting_threshold", 0.7)),
        })
        setFirewallSettings({
          autoBlockEnabled: Boolean(getValue("auto_block_enabled", true)),
          blockDurationMinutes: Number(getValue("block_duration_minutes", 60)),
          firewallSyncInterval: Number(getValue("firewall_sync_interval", 30)),
          maxConcurrentBlocks: Number(getValue("max_concurrent_blocks", 1000)),
        })
        setSystemSettings({
          learningPhase: String(getValue("learning_phase", "active")),
          pollingInterval: Number(getValue("polling_interval", 5)),
          logLevel: String(getValue("log_level", "INFO")),
          timezone: getTimezoneValue(),
        })
        setRetentionSettings({
          maxFlowsStored: Number(getValue("max_flows_stored", 10000)),
          alertRetentionDays: Number(getValue("alert_retention_days", 30)),
          cleanupIntervalHours: Number(getValue("cleanup_interval_hours", 24)),
        })
      } catch (error) {
        console.error("[Settings] Fetch error:", error)
      } finally {
        setLoading(false)
      }
    }
    fetchSettings()
  }, [])

  const updateConfigValue = async (key: string, value: string | number | boolean) => {
    const response = await fetch(
      `${API_URL}/self-healing/model-config/${key}?new_value=${encodeURIComponent(String(value))}&updated_by=dashboard`,
      { method: "POST" },
    )
    if (!response.ok) throw new Error(`Failed to update ${key}`)
  }

  const handleSave = async () => {
    setSaveStatus("saving")
    try {
      await Promise.all([
        updateConfigValue("training_threshold", mlSettings.trainingThreshold),
        updateConfigValue("alert_threshold", mlSettings.alertThreshold),
        updateConfigValue("auto_block_threshold", mlSettings.blockThreshold),
        updateConfigValue("autoencoder_retrain_days", mlSettings.autoencoderRetrainDays),
        updateConfigValue("autoencoder_min_flows", mlSettings.autoencoderMinFlows),
        updateConfigValue("ensemble_voting_threshold", mlSettings.ensembleVotingThreshold),
        updateConfigValue("auto_block_enabled", firewallSettings.autoBlockEnabled),
        updateConfigValue("block_duration_minutes", firewallSettings.blockDurationMinutes),
        updateConfigValue("firewall_sync_interval", firewallSettings.firewallSyncInterval),
        updateConfigValue("max_concurrent_blocks", firewallSettings.maxConcurrentBlocks),
        updateConfigValue("learning_phase", systemSettings.learningPhase),
        updateConfigValue("polling_interval", systemSettings.pollingInterval),
        updateConfigValue("log_level", systemSettings.logLevel),
        updateConfigValue("max_flows_stored", retentionSettings.maxFlowsStored),
        updateConfigValue("alert_retention_days", retentionSettings.alertRetentionDays),
        updateConfigValue("cleanup_interval_hours", retentionSettings.cleanupIntervalHours),
      ])
      await fetch(`${API_URL.replace(':8000', ':8001')}/admin/reload-config`, { method: "POST" }).catch(() => {})
      setSaveStatus("success")
      setTimeout(() => setSaveStatus("idle"), 2500)
    } catch (error) {
      console.error("[Settings] Save error:", error)
      setSaveStatus("error")
      setTimeout(() => setSaveStatus("idle"), 4000)
    }
  }

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <p className="text-muted-foreground text-sm">Loading settings...</p>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Settings</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Configure ML models, firewall rules, and system parameters</p>
        </div>
        <button
          onClick={handleSave}
          disabled={saveStatus === "saving"}
          className={`flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium transition-all ${
            saveStatus === "success" ? "bg-safe text-background"
            : saveStatus === "error" ? "bg-danger text-foreground"
            : "bg-primary hover:bg-primary/90 text-primary-foreground"
          } disabled:opacity-50`}
        >
          {saveStatus === "success" ? <><CheckCircle className="w-4 h-4" /> Saved</> 
           : saveStatus === "error" ? <><AlertCircle className="w-4 h-4" /> Error</> 
           : saveStatus === "saving" ? "Saving..." 
           : <><Save className="w-4 h-4" /> Save Changes</>}
        </button>
      </div>

      {/* Tab Bar */}
      <div className="flex gap-1 p-1 bg-muted rounded-xl w-fit">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              activeTab === tab.id
                ? "bg-card text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <tab.icon className="w-3.5 h-3.5" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="card-surface p-1">
        <div className="px-6">
          {activeTab === "ml" && (
            <>
              <div className="py-4 border-b border-border">
                <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Model Training</h3>
              </div>
              <SettingRow label="Training Threshold" description="Minimum flow count before the ML model begins training. Lower values train faster but may reduce accuracy.">
                <NumberInput value={mlSettings.trainingThreshold} onChange={(v) => setMLSettings({ ...mlSettings, trainingThreshold: v })} min={50} max={5000} step={50} />
              </SettingRow>
              <SettingRow label="Alert Threshold" description="Anomaly score (0-1) required to generate a security alert. Higher values reduce false positives.">
                <NumberInput value={mlSettings.alertThreshold} onChange={(v) => setMLSettings({ ...mlSettings, alertThreshold: v })} min={0} max={1} step={0.05} />
              </SettingRow>
              <SettingRow label="Auto-Block Threshold" description="Anomaly score (0-1) required for automatic IP blocking. Should be higher than alert threshold.">
                <NumberInput value={mlSettings.blockThreshold} onChange={(v) => setMLSettings({ ...mlSettings, blockThreshold: v })} min={0} max={1} step={0.05} />
              </SettingRow>
              <SettingRow label="Ensemble Voting" description="Minimum agreement ratio across ML models before a decision is made.">
                <NumberInput value={mlSettings.ensembleVotingThreshold} onChange={(v) => setMLSettings({ ...mlSettings, ensembleVotingThreshold: v })} min={0} max={1} step={0.05} />
              </SettingRow>
              <div className="py-4 border-b border-border mt-2">
                <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Autoencoder</h3>
              </div>
              <SettingRow label="Retrain Interval" description="Number of days between automatic autoencoder retraining cycles.">
                <NumberInput value={mlSettings.autoencoderRetrainDays} onChange={(v) => setMLSettings({ ...mlSettings, autoencoderRetrainDays: v })} min={1} max={30} />
              </SettingRow>
              <SettingRow label="Min Flows for Training" description="Minimum flows per device required before autoencoder training begins.">
                <NumberInput value={mlSettings.autoencoderMinFlows} onChange={(v) => setMLSettings({ ...mlSettings, autoencoderMinFlows: v })} min={50} max={1000} step={50} />
              </SettingRow>
            </>
          )}

          {activeTab === "firewall" && (
            <>
              <div className="py-4 border-b border-border">
                <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Blocking</h3>
              </div>
              <SettingRow label="Auto-Blocking" description="Automatically block IP addresses that exceed the risk threshold without manual intervention.">
                <div className="flex justify-end">
                  <Toggle checked={firewallSettings.autoBlockEnabled} onChange={(v) => setFirewallSettings({ ...firewallSettings, autoBlockEnabled: v })} />
                </div>
              </SettingRow>
              <SettingRow label="Block Duration" description="Default duration in minutes for temporary IP blocks before automatic expiration.">
                <NumberInput value={firewallSettings.blockDurationMinutes} onChange={(v) => setFirewallSettings({ ...firewallSettings, blockDurationMinutes: v })} min={5} max={1440} step={5} />
              </SettingRow>
              <SettingRow label="Sync Interval" description="How often (in seconds) firewall rules are synchronized with the system firewall.">
                <NumberInput value={firewallSettings.firewallSyncInterval} onChange={(v) => setFirewallSettings({ ...firewallSettings, firewallSyncInterval: v })} min={10} max={300} step={5} />
              </SettingRow>
              <SettingRow label="Max Concurrent Blocks" description="Maximum number of IPs that can be blocked simultaneously in the system firewall.">
                <NumberInput value={firewallSettings.maxConcurrentBlocks} onChange={(v) => setFirewallSettings({ ...firewallSettings, maxConcurrentBlocks: v })} min={100} max={10000} step={100} />
              </SettingRow>
            </>
          )}

          {activeTab === "retention" && (
            <>
              <div className="py-4 border-b border-border">
                <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Data Management</h3>
              </div>
              <SettingRow label="Max Flows Stored" description="Maximum number of flow records retained in the database before oldest records are pruned.">
                <NumberInput value={retentionSettings.maxFlowsStored} onChange={(v) => setRetentionSettings({ ...retentionSettings, maxFlowsStored: v })} min={1000} max={1000000} step={1000} />
              </SettingRow>
              <SettingRow label="Alert Retention" description="Number of days to keep security alert records before automatic deletion.">
                <NumberInput value={retentionSettings.alertRetentionDays} onChange={(v) => setRetentionSettings({ ...retentionSettings, alertRetentionDays: v })} min={1} max={365} />
              </SettingRow>
              <SettingRow label="Cleanup Interval" description="How often (in hours) the database cleanup job runs to remove expired data.">
                <NumberInput value={retentionSettings.cleanupIntervalHours} onChange={(v) => setRetentionSettings({ ...retentionSettings, cleanupIntervalHours: v })} min={1} max={168} />
              </SettingRow>
            </>
          )}

          {activeTab === "system" && (
            <>
              <div className="py-4 border-b border-border">
                <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Configuration</h3>
              </div>
              <SettingRow label="Learning Phase" description="Current operational mode of the AI detection system.">
                <SelectInput value={systemSettings.learningPhase} onChange={(v) => setSystemSettings({ ...systemSettings, learningPhase: v })} options={[
                  { value: "idle", label: "Idle" },
                  { value: "learning", label: "Learning" },
                  { value: "active", label: "Active" },
                ]} />
              </SettingRow>
              <SettingRow label="Polling Interval" description="Dashboard data refresh rate in seconds.">
                <NumberInput value={systemSettings.pollingInterval} onChange={(v) => setSystemSettings({ ...systemSettings, pollingInterval: v })} min={1} max={60} />
              </SettingRow>
              <SettingRow label="Log Level" description="Logging verbosity for the backend services.">
                <SelectInput value={systemSettings.logLevel} onChange={(v) => setSystemSettings({ ...systemSettings, logLevel: v })} options={[
                  { value: "DEBUG", label: "Debug" },
                  { value: "INFO", label: "Info" },
                  { value: "WARNING", label: "Warning" },
                  { value: "ERROR", label: "Error" },
                ]} />
              </SettingRow>
              <SettingRow label="Display Timezone" description="Timezone for all date and time displays across the dashboard.">
                <select
                  value={systemSettings.timezone}
                  onChange={(e) => {
                    const newTz = e.target.value as TimezoneOption
                    setSystemSettings({ ...systemSettings, timezone: newTz })
                    setTimezone(newTz)
                  }}
                  className="w-full h-9 px-3 bg-muted border border-border rounded-lg text-sm text-foreground focus:outline-none focus:border-primary transition-colors appearance-none cursor-pointer"
                >
                  {TIMEZONE_OPTIONS.map((tz) => <option key={tz.value} value={tz.value}>{tz.label}</option>)}
                </select>
              </SettingRow>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
