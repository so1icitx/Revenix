"use client"

import { API_URL } from '../../lib/api-config'

import { useEffect, useState, useRef, useCallback } from "react"
import { RefreshCw, X, Shield, AlertTriangle, Ban, ZoomIn, ZoomOut, Maximize2, RotateCcw, Brain } from "lucide-react"

interface ThreatPoint {
  id: string
  ip: string
  lat: number
  lng: number
  country: string
  city: string
  threatLevel: "critical" | "high" | "medium" | "low"
  attackType: string
  count: number
  lastSeen: string
  srcPort?: number
  dstPort?: number
  protocol?: string
  reason?: string
}

const THREAT_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high: "#F97316",
  medium: "#FBBF24",
  low: "#3B82F6",
}

const isPrivateIP = (ip: string): boolean => {
  if (!ip) return true
  return (
    ip.startsWith("192.168.") ||
    ip.startsWith("10.") ||
    ip.startsWith("172.16.") ||
    ip.startsWith("172.17.") ||
    ip.startsWith("172.18.") ||
    ip.startsWith("172.19.") ||
    ip.startsWith("172.2") ||
    ip.startsWith("172.30.") ||
    ip.startsWith("172.31.") ||
    ip.startsWith("127.") ||
    ip === "localhost" ||
    ip === "0.0.0.0"
  )
}

const getRandomGeoForLocalIP = () => {
  // Random locations around the world for visual effect
  const locations = [
    { lat: 42.6977, lng: 23.3219, country: "Bulgaria", city: "Sofia" },
    { lat: 40.7128, lng: -74.006, country: "USA", city: "New York" },
    { lat: 51.5074, lng: -0.1278, country: "UK", city: "London" },
    { lat: 35.6762, lng: 139.6503, country: "Japan", city: "Tokyo" },
    { lat: 52.52, lng: 13.405, country: "Germany", city: "Berlin" },
    { lat: -33.8688, lng: 151.2093, country: "Australia", city: "Sydney" },
    { lat: 55.7558, lng: 37.6173, country: "Russia", city: "Moscow" },
    { lat: 39.9042, lng: 116.4074, country: "China", city: "Beijing" },
  ]
  return locations[Math.floor(Math.random() * locations.length)]
}

export default function ThreatMapPage() {
  const [threats, setThreats] = useState<ThreatPoint[]>([])
  const [selectedThreat, setSelectedThreat] = useState<ThreatPoint | null>(null)
  const [loading, setLoading] = useState(true)
  const [autoRotate, setAutoRotate] = useState(true)
  const [isFullscreen, setIsFullscreen] = useState(false)
  const [globeReady, setGlobeReady] = useState(false)

  const containerRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const sceneRef = useRef<any>(null)
  const rendererRef = useRef<any>(null)
  const cameraRef = useRef<any>(null)
  const globeRef = useRef<any>(null)
  const controlsRef = useRef<any>(null)
  const markersRef = useRef<any[]>([])
  const frameIdRef = useRef<number>(0)
  const autoRotateRef = useRef(true)
  const threatPositionsRef = useRef<Map<string, { x: number; y: number; z: number }>>(new Map())

  // Sync autoRotate ref
  useEffect(() => {
    autoRotateRef.current = autoRotate
  }, [autoRotate])

  const fetchThreats = useCallback(async () => {
    console.log("[v0] fetchThreats called")
    try {
      const response = await fetch(`${API_URL}/alerts/recent?limit=50`)
      console.log("[v0] Response status:", response.status)
      if (!response.ok) {
        console.log("[v0] Response not ok, stopping")
        setLoading(false)
        return
      }

      const alerts = await response.json()
      console.log("[v0] Alerts received:", alerts.length, alerts)
      const threatPoints: ThreatPoint[] = []

      for (const alert of alerts.slice(0, 20)) {
        console.log("[v0] Processing alert:", alert.id, alert.src_ip, "isPrivate:", isPrivateIP(alert.src_ip))
        try {
          if (isPrivateIP(alert.src_ip)) {
            const randomGeo = getRandomGeoForLocalIP()
            threatPoints.push({
              id: `${alert.id}`,
              ip: alert.src_ip,
              lat: randomGeo.lat,
              lng: randomGeo.lng,
              country: `${randomGeo.country} (Local IP)`,
              city: randomGeo.city,
              threatLevel: alert.severity?.toLowerCase() || "medium",
              attackType: alert.category || "Unknown",
              count: 1,
              lastSeen: alert.created_at,
              srcPort: alert.src_port,
              dstPort: alert.dst_port,
              protocol: alert.protocol,
              reason: alert.reason,
            })
            console.log("[v0] Added local IP threat:", alert.src_ip)
            continue
          }

          console.log("[v0] Fetching geo for:", alert.src_ip)
          const geoRes = await fetch(`https://ipwho.is/${alert.src_ip}`)
          const geo = await geoRes.json()
          console.log("[v0] Geo result for", alert.src_ip, ":", geo)

          if (geo.success && geo.latitude && geo.longitude) {
            threatPoints.push({
              id: `${alert.id}`,
              ip: alert.src_ip,
              lat: geo.latitude,
              lng: geo.longitude,
              country: geo.country || "Unknown",
              city: geo.city || "Unknown",
              threatLevel: alert.severity?.toLowerCase() || "medium",
              attackType: alert.category || "Unknown",
              count: 1,
              lastSeen: alert.created_at,
              srcPort: alert.src_port,
              dstPort: alert.dst_port,
              protocol: alert.protocol,
              reason: alert.reason,
            })
          } else {
            const randomGeo = getRandomGeoForLocalIP()
            threatPoints.push({
              id: `${alert.id}`,
              ip: alert.src_ip,
              lat: randomGeo.lat,
              lng: randomGeo.lng,
              country: `${randomGeo.country} (Geo Failed)`,
              city: randomGeo.city,
              threatLevel: alert.severity?.toLowerCase() || "medium",
              attackType: alert.category || "Unknown",
              count: 1,
              lastSeen: alert.created_at,
              srcPort: alert.src_port,
              dstPort: alert.dst_port,
              protocol: alert.protocol,
              reason: alert.reason,
            })
            console.log("[v0] Geo lookup failed for:", alert.src_ip)
          }
        } catch {
          const randomGeo = getRandomGeoForLocalIP()
          threatPoints.push({
            id: `${alert.id}`,
            ip: alert.src_ip,
            lat: randomGeo.lat,
            lng: randomGeo.lng,
            country: `Unknown (Error)`,
            city: "Unknown",
            threatLevel: alert.severity?.toLowerCase() || "medium",
            attackType: alert.category || "Unknown",
            count: 1,
            lastSeen: alert.created_at,
            srcPort: alert.src_port,
            dstPort: alert.dst_port,
            protocol: alert.protocol,
            reason: alert.reason,
          })
        }
      }

      console.log("[v0] Total threat points:", threatPoints.length)
      setThreats(threatPoints)
    } catch (error) {
      console.error("[ThreatMap] Failed to fetch:", error)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchThreats()
    const interval = setInterval(fetchThreats, 60000)
    return () => clearInterval(interval)
  }, [fetchThreats])

  // Initialize Three.js scene
  useEffect(() => {
    if (!canvasRef.current || !containerRef.current) return

    let THREE: any

    const initScene = async () => {
      THREE = await import("three")
      const { OrbitControls } = await import("three/examples/jsm/controls/OrbitControls.js")

      const container = containerRef.current!
      const canvas = canvasRef.current!
      const width = container.clientWidth
      const height = container.clientHeight

      // Scene
      const scene = new THREE.Scene()
      scene.background = new THREE.Color(0x030712)
      sceneRef.current = scene

      // Camera
      const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000)
      camera.position.z = 3
      cameraRef.current = camera

      // Renderer with high quality settings
      const renderer = new THREE.WebGLRenderer({
        canvas,
        antialias: true,
        alpha: true,
        powerPreference: "high-performance",
      })
      renderer.setSize(width, height)
      renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
      rendererRef.current = renderer

      // Controls
      const controls = new OrbitControls(camera, canvas)
      controls.enableDamping = true
      controls.dampingFactor = 0.05
      controls.rotateSpeed = 0.5
      controls.zoomSpeed = 0.8
      controls.minDistance = 1.5
      controls.maxDistance = 5
      controls.enablePan = false
      controlsRef.current = controls

      // Starfield background
      const starsGeometry = new THREE.BufferGeometry()
      const starPositions = new Float32Array(3000 * 3)
      for (let i = 0; i < 3000 * 3; i += 3) {
        const radius = 50 + Math.random() * 100
        const theta = Math.random() * Math.PI * 2
        const phi = Math.acos(2 * Math.random() - 1)
        starPositions[i] = radius * Math.sin(phi) * Math.cos(theta)
        starPositions[i + 1] = radius * Math.sin(phi) * Math.sin(theta)
        starPositions[i + 2] = radius * Math.cos(phi)
      }
      starsGeometry.setAttribute("position", new THREE.BufferAttribute(starPositions, 3))
      const starsMaterial = new THREE.PointsMaterial({ color: 0xffffff, size: 0.15, sizeAttenuation: true })
      const stars = new THREE.Points(starsGeometry, starsMaterial)
      scene.add(stars)

      // Globe
      const textureLoader = new THREE.TextureLoader()
      const globeGeometry = new THREE.SphereGeometry(1, 64, 64)

      // Load high-res Earth textures
      const earthTexture = textureLoader.load("https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg")
      const bumpTexture = textureLoader.load("https://unpkg.com/three-globe/example/img/earth-topology.png")
      const specularTexture = textureLoader.load("https://unpkg.com/three-globe/example/img/earth-water.png")

      const globeMaterial = new THREE.MeshPhongMaterial({
        map: earthTexture,
        bumpMap: bumpTexture,
        bumpScale: 0.03,
        specularMap: specularTexture,
        specular: new THREE.Color(0x333333),
        shininess: 5,
      })

      const globe = new THREE.Mesh(globeGeometry, globeMaterial)
      scene.add(globe)
      globeRef.current = globe

      // Atmosphere glow
      const atmosphereGeometry = new THREE.SphereGeometry(1.02, 64, 64)
      const atmosphereMaterial = new THREE.ShaderMaterial({
        vertexShader: `
          varying vec3 vNormal;
          void main() {
            vNormal = normalize(normalMatrix * normal);
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }
        `,
        fragmentShader: `
          varying vec3 vNormal;
          void main() {
            float intensity = pow(0.7 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 2.0);
            gl_FragColor = vec4(0.0, 0.8, 1.0, 1.0) * intensity;
          }
        `,
        blending: THREE.AdditiveBlending,
        side: THREE.BackSide,
        transparent: true,
      })
      const atmosphere = new THREE.Mesh(atmosphereGeometry, atmosphereMaterial)
      scene.add(atmosphere)

      // Outer glow
      const outerGlowGeometry = new THREE.SphereGeometry(1.15, 64, 64)
      const outerGlowMaterial = new THREE.ShaderMaterial({
        vertexShader: `
          varying vec3 vNormal;
          void main() {
            vNormal = normalize(normalMatrix * normal);
            gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
          }
        `,
        fragmentShader: `
          varying vec3 vNormal;
          void main() {
            float intensity = pow(0.5 - dot(vNormal, vec3(0.0, 0.0, 1.0)), 3.0);
            gl_FragColor = vec4(0.0, 0.6, 0.9, 0.3) * intensity;
          }
        `,
        blending: THREE.AdditiveBlending,
        side: THREE.BackSide,
        transparent: true,
      })
      const outerGlow = new THREE.Mesh(outerGlowGeometry, outerGlowMaterial)
      scene.add(outerGlow)

      // Lighting
      const ambientLight = new THREE.AmbientLight(0xffffff, 0.4)
      scene.add(ambientLight)

      const directionalLight = new THREE.DirectionalLight(0xffffff, 1)
      directionalLight.position.set(5, 3, 5)
      scene.add(directionalLight)

      const backLight = new THREE.DirectionalLight(0x00d4ff, 0.3)
      backLight.position.set(-5, -3, -5)
      scene.add(backLight)

      setGlobeReady(true)

      // Animation loop
      let lastInteraction = Date.now()

      controls.addEventListener("start", () => {
        lastInteraction = Date.now()
      })

      const animate = () => {
        frameIdRef.current = requestAnimationFrame(animate)

        // Auto-rotate when not interacting
        if (autoRotateRef.current && Date.now() - lastInteraction > 2000) {
          globe.rotation.y += 0.002
        }

        // Pulse markers
        markersRef.current.forEach((marker, i) => {
          if (marker) {
            const scale = 1 + 0.2 * Math.sin(Date.now() * 0.003 + i)
            marker.scale.setScalar(scale)
          }
        })

        controls.update()
        renderer.render(scene, camera)
      }
      animate()

      // Handle resize
      const handleResize = () => {
        if (!container) return
        const w = container.clientWidth
        const h = container.clientHeight
        camera.aspect = w / h
        camera.updateProjectionMatrix()
        renderer.setSize(w, h)
      }
      window.addEventListener("resize", handleResize)

      return () => {
        window.removeEventListener("resize", handleResize)
        cancelAnimationFrame(frameIdRef.current)
        renderer.dispose()
      }
    }

    initScene()

    return () => {
      cancelAnimationFrame(frameIdRef.current)
      if (rendererRef.current) {
        rendererRef.current.dispose()
      }
    }
  }, [])

  // Update threat markers
  useEffect(() => {
    if (!globeReady || !sceneRef.current) return

    const updateMarkers = async () => {
      const THREE = await import("three")

      // Remove old markers
      markersRef.current.forEach((marker) => {
        if (marker && sceneRef.current) {
          sceneRef.current.remove(marker)
        }
      })
      markersRef.current = []

      // Add new markers with cached positions
      threats.forEach((threat, index) => {
        let pos = threatPositionsRef.current.get(threat.id)
        if (!pos) {
          const phi = (90 - threat.lat) * (Math.PI / 180)
          const theta = (threat.lng + 180) * (Math.PI / 180)
          pos = {
            x: -1.02 * Math.sin(phi) * Math.cos(theta),
            y: 1.02 * Math.cos(phi),
            z: 1.02 * Math.sin(phi) * Math.sin(theta),
          }
          threatPositionsRef.current.set(threat.id, pos)
        }

        // Create marker
        const color = new THREE.Color(THREAT_COLORS[threat.threatLevel])
        const markerGeometry = new THREE.SphereGeometry(0.025, 16, 16)
        const markerMaterial = new THREE.MeshBasicMaterial({
          color,
          transparent: true,
          opacity: 0.9,
        })
        const marker = new THREE.Mesh(markerGeometry, markerMaterial)
        marker.position.set(pos.x, pos.y, pos.z)
        marker.userData = { threat, index }

        sceneRef.current.add(marker)
        markersRef.current.push(marker)

        // Add glow ring
        const ringGeometry = new THREE.RingGeometry(0.03, 0.045, 32)
        const ringMaterial = new THREE.MeshBasicMaterial({
          color,
          transparent: true,
          opacity: 0.4,
          side: THREE.DoubleSide,
        })
        const ring = new THREE.Mesh(ringGeometry, ringMaterial)
        ring.position.set(pos.x, pos.y, pos.z)
        ring.lookAt(0, 0, 0)
        sceneRef.current.add(ring)
        markersRef.current.push(ring)
      })
    }

    updateMarkers()
  }, [threats, globeReady])

  // Click detection
  useEffect(() => {
    if (!canvasRef.current || !cameraRef.current || !globeReady) return

    const handleClick = async (event: MouseEvent) => {
      const THREE = await import("three")
      const canvas = canvasRef.current!
      const rect = canvas.getBoundingClientRect()

      const mouse = new THREE.Vector2(
        ((event.clientX - rect.left) / rect.width) * 2 - 1,
        -((event.clientY - rect.top) / rect.height) * 2 + 1,
      )

      const raycaster = new THREE.Raycaster()
      raycaster.setFromCamera(mouse, cameraRef.current)

      const markerMeshes = markersRef.current.filter((m) => m && m.userData?.threat)
      const intersects = raycaster.intersectObjects(markerMeshes)

      if (intersects.length > 0) {
        const threat = intersects[0].object.userData.threat
        setSelectedThreat(threat)
        setAutoRotate(false)
      }
    }

    canvasRef.current.addEventListener("click", handleClick)
    return () => canvasRef.current?.removeEventListener("click", handleClick)
  }, [globeReady])

  const toggleFullscreen = () => {
    if (!containerRef.current) return
    if (!isFullscreen) {
      containerRef.current.requestFullscreen?.()
    } else {
      document.exitFullscreen?.()
    }
    setIsFullscreen(!isFullscreen)
  }

  const handleZoomIn = () => {
    if (cameraRef.current) {
      cameraRef.current.position.z = Math.max(1.5, cameraRef.current.position.z - 0.3)
    }
  }

  const handleZoomOut = () => {
    if (cameraRef.current) {
      cameraRef.current.position.z = Math.min(5, cameraRef.current.position.z + 0.3)
    }
  }

  const handleReset = () => {
    if (cameraRef.current && globeRef.current) {
      cameraRef.current.position.set(0, 0, 3)
      globeRef.current.rotation.set(0, 0, 0)
      setAutoRotate(true)
    }
  }

  const handleBlockIP = async (ip: string) => {
    try {
      await fetch(`${API_URL}/self-healing/blocked-ips`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, duration_minutes: 1440, reason: "Manual block from threat map" }),
      })
      setSelectedThreat(null)
    } catch (error) {
      console.error("Failed to block IP:", error)
    }
  }

  const criticalCount = threats.filter((t) => t.threatLevel === "critical").length
  const highCount = threats.filter((t) => t.threatLevel === "high").length

  return (
    <div ref={containerRef} className="h-[calc(100vh-56px)] bg-background relative overflow-hidden">
      {/* Canvas */}
      <canvas ref={canvasRef} className="w-full h-full" />

      {/* Loading Overlay */}
      {!globeReady && (
        <div className="absolute inset-0 flex items-center justify-center bg-background">
          <div className="text-center">
            <RefreshCw className="w-8 h-8 text-primary animate-spin mx-auto mb-3" />
            <p className="text-muted-foreground text-sm">Initializing Globe...</p>
          </div>
        </div>
      )}

      {/* Stats Bar */}
      <div className="absolute top-4 left-4 z-20 flex gap-2">
        <div className="bg-card/90 border border-border rounded-lg px-3 py-2">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Threats</p>
          <p className="text-xl font-semibold text-foreground">{threats.length}</p>
        </div>
        <div className="bg-card/90 border border-border rounded-lg px-3 py-2">
          <p className="text-[10px] text-severity-critical uppercase tracking-wider">Critical</p>
          <p className="text-xl font-semibold text-severity-critical">{criticalCount}</p>
        </div>
        <div className="bg-card/90 border border-border rounded-lg px-3 py-2">
          <p className="text-[10px] text-severity-high uppercase tracking-wider">High</p>
          <p className="text-xl font-semibold text-severity-high">{highCount}</p>
        </div>
      </div>

      {/* Controls */}
      <div className="absolute top-4 right-4 z-20 flex flex-col gap-1.5">
        {[
          { onClick: () => setAutoRotate(!autoRotate), title: autoRotate ? "Pause" : "Play", active: autoRotate, icon: autoRotate ? <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M6 4h4v16H6V4zm8 0h4v16h-4V4z" /></svg> : <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7L8 5z" /></svg> },
          { onClick: handleZoomIn, title: "Zoom in", icon: <ZoomIn className="w-4 h-4" /> },
          { onClick: handleZoomOut, title: "Zoom out", icon: <ZoomOut className="w-4 h-4" /> },
          { onClick: handleReset, title: "Reset", icon: <RotateCcw className="w-4 h-4" /> },
          { onClick: toggleFullscreen, title: "Fullscreen", icon: <Maximize2 className="w-4 h-4" /> },
          { onClick: fetchThreats, title: "Refresh", icon: <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> },
        ].map((btn, i) => (
          <button
            key={i}
            onClick={btn.onClick}
            className={`p-2.5 rounded-lg border transition-colors ${
              btn.active ? "bg-primary/15 border-primary/30 text-primary" : "bg-card/90 border-border text-muted-foreground hover:text-foreground hover:border-border-hover"
            }`}
            title={btn.title}
          >
            {btn.icon}
          </button>
        ))}
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 z-20 bg-card/90 border border-border rounded-lg p-3">
        <p className="text-[10px] text-muted-foreground mb-2 font-medium uppercase tracking-wider">Severity</p>
        <div className="space-y-1.5">
          {[
            { level: "critical", label: "Critical", color: "#EF4444" },
            { level: "high", label: "High", color: "#F97316" },
            { level: "medium", label: "Medium", color: "#FBBF24" },
            { level: "low", label: "Low", color: "#3B82F6" },
          ].map((item) => (
            <div key={item.level} className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
              <span className="text-xs text-muted-foreground">{item.label}</span>
              <span className="text-xs text-muted-foreground ml-auto font-mono">
                {threats.filter((t) => t.threatLevel === item.level).length}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Instructions */}
      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 z-20 bg-card/80 border border-border rounded-lg px-3 py-1.5">
        <p className="text-[10px] text-muted-foreground">Drag to rotate / Scroll to zoom / Click threat to inspect</p>
      </div>

      {/* Selected Threat Panel */}
      {selectedThreat && (
        <div className="absolute bottom-4 right-4 z-30 w-80 bg-card border border-border rounded-xl overflow-hidden shadow-2xl shadow-black/50 animate-fadeIn">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ backgroundColor: `${THREAT_COLORS[selectedThreat.threatLevel]}15` }}>
                <AlertTriangle className="w-4 h-4" style={{ color: THREAT_COLORS[selectedThreat.threatLevel] }} />
              </div>
              <div>
                <p className="text-xs font-semibold uppercase" style={{ color: THREAT_COLORS[selectedThreat.threatLevel] }}>{selectedThreat.threatLevel}</p>
                <p className="text-[10px] text-muted-foreground">{selectedThreat.attackType}</p>
              </div>
            </div>
            <button onClick={() => setSelectedThreat(null)} className="p-1.5 hover:bg-muted rounded-lg transition">
              <X className="w-3.5 h-3.5 text-muted-foreground" />
            </button>
          </div>
          <div className="p-4 space-y-3">
            <div className="flex items-center justify-between p-2.5 bg-muted rounded-lg">
              <div>
                <p className="text-[10px] text-muted-foreground">IP Address</p>
                <p className="text-sm font-mono text-foreground">{selectedThreat.ip}</p>
              </div>
              <div className="text-right">
                <p className="text-[10px] text-muted-foreground">Location</p>
                <p className="text-xs text-foreground">{selectedThreat.city}, {selectedThreat.country}</p>
              </div>
            </div>
            {(selectedThreat.srcPort || selectedThreat.dstPort) && (
              <div className="grid grid-cols-3 gap-2">
                <div className="p-2 bg-muted rounded-lg">
                  <p className="text-[10px] text-muted-foreground">Protocol</p>
                  <p className="text-xs font-mono text-primary">{selectedThreat.protocol || "TCP"}</p>
                </div>
                <div className="p-2 bg-muted rounded-lg">
                  <p className="text-[10px] text-muted-foreground">Src Port</p>
                  <p className="text-xs font-mono text-foreground">{selectedThreat.srcPort || "-"}</p>
                </div>
                <div className="p-2 bg-muted rounded-lg">
                  <p className="text-[10px] text-muted-foreground">Dst Port</p>
                  <p className="text-xs font-mono text-foreground">{selectedThreat.dstPort || "-"}</p>
                </div>
              </div>
            )}
            {selectedThreat.reason && (
              <div className="p-2.5 bg-muted rounded-lg">
                <p className="text-[10px] text-muted-foreground mb-1 flex items-center gap-1"><Brain className="w-3 h-3" /> AI Analysis</p>
                <p className="text-xs text-foreground leading-relaxed">{selectedThreat.reason}</p>
              </div>
            )}
            <div className="flex gap-2">
              <button onClick={() => handleBlockIP(selectedThreat.ip)} className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 bg-danger/10 hover:bg-danger/20 border border-danger/20 rounded-lg text-danger text-xs font-medium transition">
                <Ban className="w-3.5 h-3.5" /> Block
              </button>
              <button onClick={() => window.open(`/threats?ip=${selectedThreat.ip}`, "_blank")} className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 bg-primary/10 hover:bg-primary/20 border border-primary/20 rounded-lg text-primary text-xs font-medium transition">
                <Shield className="w-3.5 h-3.5" /> Investigate
              </button>
            </div>
          </div>
        </div>
      )}

      {/* No Threats Message */}
      {!loading && threats.length === 0 && globeReady && (
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-20 bg-safe/10 border border-safe/30 rounded-lg px-5 py-2.5">
          <div className="flex items-center gap-2.5">
            <Shield className="w-4 h-4 text-safe" />
            <span className="text-safe text-sm font-medium">No active threats detected</span>
          </div>
        </div>
      )}
    </div>
  )
}
