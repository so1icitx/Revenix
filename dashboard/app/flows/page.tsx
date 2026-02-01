'use client'

import { useEffect, useState, useMemo } from 'react'
import { formatSofiaDateTime } from '../../lib/time'
import { Search, SlidersHorizontal, ArrowUpDown, X } from 'lucide-react'
import { API_URL } from '../../lib/api-config'

interface Flow {
  hostname: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  packets: number
  bytes: number
  end_ts: number
  anomaly_score?: number
}

type SortField = 'packets' | 'bytes' | 'end_ts' | 'hostname'
type SortDirection = 'asc' | 'desc'

export default function FlowsPage() {
  const [flows, setFlows] = useState<Flow[]>([])
  const [searchIP, setSearchIP] = useState('')
  const [searchDevice, setSearchDevice] = useState('')
  const [searchPort, setSearchPort] = useState('')
  const [protocolFilter, setProtocolFilter] = useState<string>('all')
  const [sortField, setSortField] = useState<SortField>('packets')
  const [sortDirection, setSortDirection] = useState<SortDirection>('desc')
  const [showFilters, setShowFilters] = useState(false)

  useEffect(() => {
    const fetchFlows = async () => {
      try {
        const response = await fetch(`${API_URL}/flows/recent`)
        if (!response.ok) throw new Error('Failed to fetch')
        setFlows(await response.json())
      } catch (error) {
        console.error('[Flows] Fetch error:', error)
      }
    }
    fetchFlows()
    const interval = setInterval(fetchFlows, 2000)
    return () => clearInterval(interval)
  }, [])

  const protocols = useMemo(() => {
    return Array.from(new Set(flows.map(f => f.protocol))).sort()
  }, [flows])

  const filteredFlows = useMemo(() => {
    let filtered = flows
    if (protocolFilter !== 'all') filtered = filtered.filter(f => f.protocol === protocolFilter)
    if (searchIP.trim()) {
      const s = searchIP.trim().toLowerCase()
      filtered = filtered.filter(f => f.src_ip.toLowerCase().includes(s) || f.dst_ip.toLowerCase().includes(s))
    }
    if (searchDevice.trim()) {
      const s = searchDevice.trim().toLowerCase()
      filtered = filtered.filter(f => f.hostname.toLowerCase().includes(s))
    }
    if (searchPort.trim()) {
      filtered = filtered.filter(f => f.src_port?.toString().includes(searchPort.trim()) || f.dst_port?.toString().includes(searchPort.trim()))
    }
    filtered.sort((a, b) => {
      let cmp = 0
      switch (sortField) {
        case 'packets': cmp = a.packets - b.packets; break
        case 'bytes': cmp = a.bytes - b.bytes; break
        case 'end_ts': cmp = a.end_ts - b.end_ts; break
        case 'hostname': cmp = a.hostname.localeCompare(b.hostname); break
      }
      return sortDirection === 'asc' ? cmp : -cmp
    })
    return filtered
  }, [flows, protocolFilter, searchIP, searchDevice, searchPort, sortField, sortDirection])

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDirection(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(field); setSortDirection('desc') }
  }

  const clearFilters = () => {
    setSearchIP(''); setSearchDevice(''); setSearchPort('')
    setProtocolFilter('all'); setSortField('packets'); setSortDirection('desc')
  }

  const hasActiveFilters = searchIP || searchDevice || searchPort || protocolFilter !== 'all'

  const SortIcon = ({ field }: { field: SortField }) => (
    <ArrowUpDown className={`w-3 h-3 ${sortField === field ? 'text-primary' : 'opacity-30'} ${sortField === field && sortDirection === 'asc' ? 'rotate-180' : ''}`} />
  )

  const formatBytes = (bytes: number) => {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${bytes} B`
  }

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Network Flows</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Historical flow data and aggregated traffic</p>
        </div>
        <button
          onClick={() => setShowFilters(!showFilters)}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
            showFilters || hasActiveFilters
              ? 'bg-primary text-primary-foreground'
              : 'bg-card text-muted-foreground border border-border hover:border-border-hover'
          }`}
        >
          <SlidersHorizontal className="w-3.5 h-3.5" />
          Filters {hasActiveFilters && `(${[searchIP, searchDevice, searchPort, protocolFilter !== 'all'].filter(Boolean).length})`}
        </button>
      </div>

      {/* Filter Panel */}
      {showFilters && (
        <div className="card-surface p-4 animate-fadeIn">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { label: 'Search by IP', value: searchIP, onChange: setSearchIP, placeholder: 'e.g., 192.168.1.1' },
              { label: 'Search by Device', value: searchDevice, onChange: setSearchDevice, placeholder: 'e.g., server01' },
              { label: 'Search by Port', value: searchPort, onChange: setSearchPort, placeholder: 'e.g., 443, 80' },
            ].map((field) => (
              <div key={field.label}>
                <label className="block text-[11px] text-muted-foreground mb-1.5 uppercase tracking-wider">{field.label}</label>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
                  <input
                    type="text"
                    placeholder={field.placeholder}
                    value={field.value}
                    onChange={(e) => field.onChange(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 bg-muted border border-border rounded-lg text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary transition-colors"
                  />
                </div>
              </div>
            ))}
            <div>
              <label className="block text-[11px] text-muted-foreground mb-1.5 uppercase tracking-wider">Protocol</label>
              <select
                value={protocolFilter}
                onChange={(e) => setProtocolFilter(e.target.value)}
                className="w-full px-3 py-2 bg-muted border border-border rounded-lg text-sm text-foreground focus:outline-none focus:border-primary"
              >
                <option value="all">All Protocols</option>
                {protocols.map(p => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
          </div>
          {hasActiveFilters && (
            <div className="flex justify-end mt-3">
              <button onClick={clearFilters} className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground bg-muted rounded-lg transition-colors">
                <X className="w-3 h-3" /> Clear Filters
              </button>
            </div>
          )}
        </div>
      )}

      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>Showing {filteredFlows.length} of {flows.length} flows</span>
        <span>Sorted by: {sortField} ({sortDirection === 'desc' ? 'highest first' : 'lowest first'})</span>
      </div>

      {/* Table */}
      <div className="card-surface overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                {[
                  { label: 'Device', field: 'hostname' as SortField, sortable: true },
                  { label: 'Source', sortable: false },
                  { label: 'Dest', sortable: false },
                  { label: 'Src Port', sortable: false },
                  { label: 'Dst Port', sortable: false },
                  { label: 'Protocol', sortable: false },
                  { label: 'Packets', field: 'packets' as SortField, sortable: true },
                  { label: 'Bytes', field: 'bytes' as SortField, sortable: true },
                  { label: 'Time', field: 'end_ts' as SortField, sortable: true },
                ].map((col) => (
                  <th
                    key={col.label}
                    className={`px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider ${col.sortable ? 'cursor-pointer hover:text-foreground' : ''}`}
                    onClick={() => col.sortable && col.field && toggleSort(col.field)}
                  >
                    <div className="flex items-center gap-1.5">
                      {col.label}
                      {col.sortable && col.field && <SortIcon field={col.field} />}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredFlows.length === 0 ? (
                <tr><td colSpan={9} className="px-4 py-8 text-center text-muted-foreground text-sm">{hasActiveFilters ? 'No flows match your filters' : 'No flows available'}</td></tr>
              ) : (
                filteredFlows.map((flow, idx) => (
                  <tr key={idx} className="border-b border-border last:border-0 hover:bg-muted/50 transition-colors">
                    <td className="px-4 py-2.5 text-sm text-primary font-medium">{flow.hostname}</td>
                    <td className="px-4 py-2.5 text-sm font-mono text-muted-foreground">{flow.src_ip}</td>
                    <td className="px-4 py-2.5 text-sm font-mono text-muted-foreground">{flow.dst_ip}</td>
                    <td className="px-4 py-2.5 text-sm font-mono text-muted-foreground">{flow.src_port || '-'}</td>
                    <td className="px-4 py-2.5 text-sm font-mono text-muted-foreground">{flow.dst_port || '-'}</td>
                    <td className="px-4 py-2.5 text-sm"><span className="px-2 py-0.5 bg-muted rounded text-xs">{flow.protocol}</span></td>
                    <td className="px-4 py-2.5 text-sm font-semibold text-foreground">{flow.packets.toLocaleString()}</td>
                    <td className="px-4 py-2.5 text-sm text-foreground">{formatBytes(flow.bytes)}</td>
                    <td className="px-4 py-2.5 text-sm text-muted-foreground whitespace-nowrap">
                      {formatSofiaDateTime(flow.end_ts * 1000, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
