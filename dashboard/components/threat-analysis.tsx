"use client"

interface ThreatAnalysisProps {
  reason: string
  srcIp: string
  dstIp: string
  protocol?: string
  srcPort?: number
  dstPort?: number
  riskScore: number
  severity: string
  threatCategory?: string
}

export function ThreatAnalysis({
  reason,
  srcIp,
  dstIp,
  protocol,
  srcPort,
  dstPort,
  riskScore,
  severity,
  threatCategory,
}: ThreatAnalysisProps) {
  // Parse the markdown-like reason into structured sections
  const sections = parseAnalysis(reason)

  const getSeverityStyle = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return { bg: "bg-severity-critical/10", border: "border-severity-critical/20", text: "text-severity-critical", dot: "bg-severity-critical" }
      case "high":
        return { bg: "bg-severity-high/10", border: "border-severity-high/20", text: "text-severity-high", dot: "bg-severity-high" }
      case "medium":
        return { bg: "bg-severity-medium/10", border: "border-severity-medium/20", text: "text-severity-medium", dot: "bg-severity-medium" }
      default:
        return { bg: "bg-severity-low/10", border: "border-severity-low/20", text: "text-severity-low", dot: "bg-severity-low" }
    }
  }

  const style = getSeverityStyle(severity)

  return (
    <div className="space-y-4">
      {/* Header Card */}
      <div className={`${style.bg} ${style.border} border rounded-lg p-4`}>
        <div className="flex items-center gap-3 mb-2">
          <div className={`w-2 h-2 rounded-full ${style.dot}`} />
          <span className={`text-xs font-semibold uppercase ${style.text}`}>{severity} Severity</span>
          <span className="text-muted-foreground text-xs">|</span>
          <span className="text-foreground font-mono text-xs">{(riskScore * 100).toFixed(0)}% Risk</span>
        </div>
        {threatCategory && (
          <div className="inline-block px-2 py-0.5 bg-muted rounded text-[11px] text-muted-foreground">
            {threatCategory.replace(/_/g, " ")}
          </div>
        )}
      </div>

      {/* Connection Info */}
      <div className="bg-muted border border-border rounded-lg p-4">
        <h4 className="text-[10px] uppercase text-muted-foreground mb-3 font-medium tracking-wider">Connection Details</h4>
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <p className="text-[10px] text-muted-foreground mb-0.5">Source</p>
            <p className="font-mono text-primary text-sm">{srcIp}</p>
            {srcPort && <p className="text-[11px] text-muted-foreground">Port {srcPort}</p>}
          </div>
          <div className="flex flex-col items-center">
            <div className="text-muted-foreground text-xs">{">"}</div>
            {protocol && <span className="text-[10px] px-1.5 py-0.5 bg-background rounded text-muted-foreground mt-1">{protocol}</span>}
          </div>
          <div className="flex-1 text-right">
            <p className="text-[10px] text-muted-foreground mb-0.5">Destination</p>
            <p className="font-mono text-foreground text-sm">{dstIp}</p>
            {dstPort && <p className="text-[11px] text-muted-foreground">Port {dstPort}</p>}
          </div>
        </div>
      </div>

      {/* Analysis Sections */}
      {sections.map((section, idx) => (
        <div key={idx} className="bg-muted/50 border border-border rounded-lg overflow-hidden">
          {section.title && (
            <div className="px-4 py-2 bg-muted border-b border-border">
              <h4 className="text-sm font-medium text-foreground">{section.title}</h4>
            </div>
          )}
          <div className="p-4">
            {section.items.length > 0 ? (
              <ul className="space-y-1.5">
                {section.items.map((item, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-foreground/80">
                    <span className="text-primary mt-0.5 text-xs">-</span>
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-foreground/80 leading-relaxed whitespace-pre-wrap">{section.content}</p>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

interface Section {
  title?: string
  content: string
  items: string[]
}

function parseAnalysis(reason: string): Section[] {
  if (!reason) return [{ content: "No analysis available.", items: [] }]

  const sections: Section[] = []

  // Remove emoji prefixes and clean up
  const cleanReason = reason
    .replace(/[🚨🔴🟠🟡🔵⚠️🔒🧅🔄🏢🔍🤖]/gu, "")
    .replace(/\*\*/g, "")
    .trim()

  // Split by --- or ### headers
  const parts = cleanReason.split(/(?=###)|(?=---)/).filter((p) => p.trim())

  for (const part of parts) {
    const trimmed = part.trim()

    if (trimmed.startsWith("---")) {
      continue // Skip dividers
    }

    if (trimmed.startsWith("###")) {
      const lines = trimmed.split("\n")
      const title = lines[0].replace(/^###\s*/, "").trim()
      const content = lines.slice(1).join("\n").trim()

      // Extract bullet points
      const items: string[] = []
      const nonBulletContent: string[] = []

      for (const line of content.split("\n")) {
        const trimmedLine = line.trim()
        if (trimmedLine.startsWith("-") || trimmedLine.startsWith("•")) {
          items.push(trimmedLine.replace(/^[-•]\s*/, ""))
        } else if (trimmedLine) {
          nonBulletContent.push(trimmedLine)
        }
      }

      sections.push({
        title,
        content: nonBulletContent.join("\n"),
        items,
      })
    } else if (trimmed) {
      // Regular paragraph
      const lines = trimmed.split("\n")
      const items: string[] = []
      const nonBulletContent: string[] = []

      for (const line of lines) {
        const trimmedLine = line.trim()
        if (trimmedLine.startsWith("-") || trimmedLine.startsWith("•")) {
          items.push(trimmedLine.replace(/^[-•]\s*/, ""))
        } else if (trimmedLine) {
          nonBulletContent.push(trimmedLine)
        }
      }

      if (nonBulletContent.length > 0 || items.length > 0) {
        sections.push({
          content: nonBulletContent.join("\n"),
          items,
        })
      }
    }
  }

  return sections.length > 0 ? sections : [{ content: reason, items: [] }]
}
