"use client"

import React, { useEffect, useRef, useCallback, useState } from "react"
import createGlobe from "cobe"

export interface PulseMarker {
  id: string
  location: [number, number]
  delay?: number
  size?: number
}

export interface GlobePulseProps {
  markers?: PulseMarker[]
  className?: string
  speed?: number
  baseColor?: [number, number, number]
  markerColor?: [number, number, number]
  glowColor?: [number, number, number]
  arcColor?: [number, number, number]
  arcs?: Array<{ from: [number, number]; to: [number, number] }>
}

const defaultMarkers: PulseMarker[] = [
  { id: "fra", location: [50.11, 8.68], delay: 0, size: 0.04 },
  { id: "zrh", location: [47.37, 8.54], delay: 0.4, size: 0.035 },
  { id: "lnd", location: [51.51, -0.13], delay: 0.8, size: 0.035 },
  { id: "sjc", location: [37.33, -121.88], delay: 1.2, size: 0.04 },
  { id: "blr", location: [12.97, 77.59], delay: 1.6, size: 0.045 },
  { id: "sin", location: [1.35, 103.82], delay: 2.0, size: 0.035 },
  { id: "tyo", location: [35.68, 139.65], delay: 2.4, size: 0.035 },
]

const defaultArcs = [
  { from: [37.33, -121.88] as [number, number], to: [50.11, 8.68] as [number, number] },
  { from: [50.11, 8.68] as [number, number], to: [51.51, -0.13] as [number, number] },
  { from: [51.51, -0.13] as [number, number], to: [12.97, 77.59] as [number, number] },
]

export function GlobePulse({
  markers = defaultMarkers,
  className = "",
  speed = 0.003,
  baseColor = [0.35, 0.38, 0.48],
  markerColor = [0.79, 0.68, 0.65],
  glowColor = [0.08, 0.12, 0.2],
  arcColor = [0.79, 0.68, 0.65],
  arcs = defaultArcs,
}: GlobePulseProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const pointerInteracting = useRef<{ x: number; y: number } | null>(null)
  const dragOffset = useRef({ phi: 0, theta: 0 })
  const phiOffsetRef = useRef(0.8)
  const thetaOffsetRef = useRef(0.25)
  const isPausedRef = useRef(false)
  const [isLoaded, setIsLoaded] = useState(false)

  const handlePointerDown = useCallback((e: React.PointerEvent) => {
    pointerInteracting.current = { x: e.clientX, y: e.clientY }
    if (canvasRef.current) canvasRef.current.style.cursor = "grabbing"
    isPausedRef.current = true
  }, [])

  const handlePointerUp = useCallback(() => {
    if (pointerInteracting.current !== null) {
      phiOffsetRef.current += dragOffset.current.phi
      thetaOffsetRef.current = Math.max(-0.6, Math.min(0.6, thetaOffsetRef.current + dragOffset.current.theta))
      dragOffset.current = { phi: 0, theta: 0 }
    }
    pointerInteracting.current = null
    if (canvasRef.current) canvasRef.current.style.cursor = "grab"
    isPausedRef.current = false
  }, [])

  useEffect(() => {
    const handlePointerMove = (e: PointerEvent) => {
      if (pointerInteracting.current !== null) {
        dragOffset.current = {
          phi: (e.clientX - pointerInteracting.current.x) / 250,
          theta: (e.clientY - pointerInteracting.current.y) / 400,
        }
      }
    }
    window.addEventListener("pointermove", handlePointerMove, { passive: true })
    window.addEventListener("pointerup", handlePointerUp, { passive: true })
    return () => {
      window.removeEventListener("pointermove", handlePointerMove)
      window.removeEventListener("pointerup", handlePointerUp)
    }
  }, [handlePointerUp])

  useEffect(() => {
    const canvas = canvasRef.current
    const container = containerRef.current
    if (!canvas || !container) return

    let globe: ReturnType<typeof createGlobe> | null = null
    let animationId: number
    let phi = 0
    let width = container.offsetWidth || 500

    function initGlobe() {
      if (globe || !canvas) return
      width = container?.offsetWidth || 500
      if (width === 0) width = 500

      const dpr = Math.min(window.devicePixelRatio || 1, 2)

      try {
        globe = createGlobe(canvas, {
          devicePixelRatio: dpr,
          width: width,
          height: width,
          phi: phiOffsetRef.current,
          theta: thetaOffsetRef.current,
          dark: 1,
          diffuse: 1.6,
          mapSamples: 16000,
          mapBrightness: 8,
          mapBaseBrightness: 0.1,
          baseColor: baseColor,
          markerColor: markerColor,
          glowColor: glowColor,
          markerElevation: 0.05,
          markers: markers.map((m) => ({
            location: m.location,
            size: m.size || 0.035,
            id: m.id,
          })),
          arcs: arcs.map((a) => ({ from: a.from, to: a.to })),
          arcColor: arcColor,
          arcWidth: 0.7,
          arcHeight: 0.28,
          opacity: 0.85,
        })

        function animate() {
          if (!isPausedRef.current) {
            phi += speed
          }
          if (globe) {
            const currentTheta = Math.max(
              -0.6,
              Math.min(0.6, thetaOffsetRef.current + dragOffset.current.theta)
            )
            globe.update({
              phi: phi + phiOffsetRef.current + dragOffset.current.phi,
              theta: currentTheta,
            })
          }
          animationId = requestAnimationFrame(animate)
        }

        animate()
        setIsLoaded(true)
      } catch (err) {
        console.error("Failed to initialize Cobe globe:", err)
      }
    }

    // Initialize immediately or observe resize
    if (container.offsetWidth > 0) {
      initGlobe()
    }

    const ro = new ResizeObserver((entries) => {
      const entryWidth = entries[0]?.contentRect.width
      if (entryWidth && entryWidth > 0 && !globe) {
        initGlobe()
      }
    })
    ro.observe(container)

    return () => {
      if (animationId) cancelAnimationFrame(animationId)
      if (globe) globe.destroy()
      ro.disconnect()
    }
  }, [markers, speed, baseColor, markerColor, glowColor, arcColor, arcs])

  return (
    <div
      ref={containerRef}
      className={`relative aspect-square w-full select-none flex items-center justify-center ${className}`}
      style={{ touchAction: "none" }}
    >
      <canvas
        ref={canvasRef}
        onPointerDown={handlePointerDown}
        style={{
          width: "100%",
          height: "100%",
          maxWidth: "100%",
          maxHeight: "100%",
          cursor: "grab",
          opacity: isLoaded ? 1 : 0,
          transition: "opacity 0.8s ease-in-out",
          borderRadius: "50%",
        }}
      />
    </div>
  )
}

export default GlobePulse
