import React, { useEffect, useRef, useState, useCallback } from 'react';
import './ForensicGlobe.css';

interface ForensicNode {
  id: string;
  name: string;
  city: string;
  country: string;
  ip: string;
  type: 'origin' | 'relay' | 'destination' | 'sentinel';
  lat: number;
  lon: number;
  status: 'flagged' | 'verified' | 'analyzing';
  asn: string;
}

interface ForensicArc {
  id: string;
  from: string;
  to: string;
  label: string;
  speed: number;
  color: string;
  active: boolean;
}

interface ClickPulse {
  id: number;
  x: number;
  y: number;
  lat: number;
  lon: number;
  radius: number;
  maxRadius: number;
  alpha: number;
}

const FORENSIC_NODES: ForensicNode[] = [
  {
    id: 'sjc',
    name: 'MUA Origin Client',
    city: 'San Jose',
    country: 'United States',
    ip: '104.244.42.1',
    type: 'origin',
    lat: 37.3382,
    lon: -121.8863,
    status: 'flagged',
    asn: 'AS13414 (Origin Spoof)',
  },
  {
    id: 'fra',
    name: 'Primary Ingress Relay',
    city: 'Frankfurt',
    country: 'Germany',
    ip: '194.26.29.112',
    type: 'relay',
    lat: 50.1109,
    lon: 8.6821,
    status: 'flagged',
    asn: 'AS9009 (Bulletproof Hosting)',
  },
  {
    id: 'lnd',
    name: 'Edge Gateway Sentinel',
    city: 'London',
    country: 'United Kingdom',
    ip: '51.140.82.19',
    type: 'sentinel',
    lat: 51.5074,
    lon: -0.1278,
    status: 'verified',
    asn: 'AS8075 (Inspection Hop)',
  },
  {
    id: 'blr',
    name: 'Target Ingestion Gateway',
    city: 'Bengaluru',
    country: 'India',
    ip: '115.240.90.14',
    type: 'destination',
    lat: 12.9716,
    lon: 77.5946,
    status: 'verified',
    asn: 'AS9498 (Corporate Ingress)',
  },
  {
    id: 'tyo',
    name: 'East-Asia Telemetry Node',
    city: 'Tokyo',
    country: 'Japan',
    ip: '133.242.18.9',
    type: 'sentinel',
    lat: 35.6762,
    lon: 139.6503,
    status: 'verified',
    asn: 'AS9370 (Monitored Hub)',
  },
];

const FORENSIC_ARCS: ForensicArc[] = [
  {
    id: 'arc-1',
    from: 'sjc',
    to: 'fra',
    label: 'Hop 01: Ingress Relay Header Trace',
    speed: 0.75,
    color: 'rgba(216, 195, 207, 0.75)',
    active: true,
  },
  {
    id: 'arc-2',
    from: 'fra',
    to: 'lnd',
    label: 'Hop 02: DKIM / SPF Cross-Check',
    speed: 0.6,
    color: 'rgba(201, 173, 167, 0.8)',
    active: true,
  },
  {
    id: 'arc-3',
    from: 'lnd',
    to: 'blr',
    label: 'Hop 03: Gateway Ingestion',
    speed: 0.8,
    color: 'rgba(242, 233, 228, 0.85)',
    active: true,
  },
];

// Polygonal bounds checking for recognizable world landmasses
const isLandCoordinate = (lat: number, lon: number): boolean => {
  // North America
  if (lat >= 14 && lat <= 72 && lon >= -168 && lon <= -52) {
    if (lat < 30 && lon < -105) return false;
    if (lat > 55 && lon > -50) return false;
    return true;
  }
  // Central America
  if (lat >= 7 && lat < 14 && lon >= -92 && lon <= -77) return true;
  // South America
  if (lat >= -56 && lat <= 13 && lon >= -82 && lon <= -34) {
    if (lat < -20 && lon > -40) return false;
    if (lat > 0 && lon < -80) return false;
    return true;
  }
  // Europe
  if (lat >= 36 && lat <= 71 && lon >= -10 && lon <= 45) {
    return true;
  }
  // Africa
  if (lat >= -35 && lat <= 37 && lon >= -18 && lon <= 52) {
    if (lat > 20 && lon < -15) return false;
    if (lat < -10 && lon < 10) return false;
    return true;
  }
  // Asia
  if (lat >= 5 && lat <= 75 && lon >= 45 && lon <= 180) {
    if (lat < 10 && lon > 85 && lon < 98) return false;
    return true;
  }
  // India subcontinent
  if (lat >= 8 && lat <= 35 && lon >= 68 && lon <= 90) return true;
  // Japan
  if (lat >= 30 && lat <= 46 && lon >= 129 && lon <= 146) return true;
  // Southeast Asia & Indonesia
  if (lat >= -11 && lat <= 20 && lon >= 95 && lon <= 142) return true;
  // Australia & New Zealand
  if (lat >= -44 && lat <= -10 && lon >= 112 && lon <= 178) {
    if (lat < -38 && lon < 165 && lon > 148) return false;
    return true;
  }
  // United Kingdom & Ireland
  if (lat >= 50 && lat <= 59 && lon >= -11 && lon <= 2) return true;

  return false;
};

// Generate high-density fine dot-matrix across the sphere
interface SpherePoint {
  lat: number;
  lon: number;
  isLand: boolean;
}

const generateGlobeDots = (totalSamples: number): SpherePoint[] => {
  const points: SpherePoint[] = [];
  const goldenRatio = (1 + Math.sqrt(5)) / 2;

  for (let i = 0; i < totalSamples; i++) {
    const theta = (2 * Math.PI * i) / goldenRatio;
    const phi = Math.acos(1 - (2 * (i + 0.5)) / totalSamples);

    const lat = 90 - (phi * 180) / Math.PI;
    const lon = ((theta * 180) / Math.PI) % 360 - 180;
    const isLand = isLandCoordinate(lat, lon);

    // Keep land dots only for pure, clean negative space
    if (isLand) {
      points.push({ lat, lon, isLand: true });
    }
  }
  return points;
};

const GLOBE_POINTS = generateGlobeDots(4800);

export const ForensicGlobe: React.FC<{ className?: string }> = ({ className = '' }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [hoveredNode, setHoveredNode] = useState<ForensicNode | null>(null);
  const [tooltipPos, setTooltipPos] = useState<{ x: number; y: number } | null>(null);
  const hoveredNodeRef = useRef<ForensicNode | null>(null);
  hoveredNodeRef.current = hoveredNode;

  const pulsesRef = useRef<ClickPulse[]>([]);

  // Rotation & Interactive Physics
  const rotYRef = useRef<number>(0.85);
  const rotXRef = useRef<number>(0.26);
  const baseSpeedRef = useRef<number>(0.0016); // Slow, dignified rotation
  const mouseOffsetRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const isDraggingRef = useRef<boolean>(false);
  const lastMousePosRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const nodeScreenMapRef = useRef<Map<string, { x: number; y: number; z: number; node: ForensicNode }>>(new Map());

  // Mouse / Touch Drag handlers
  const handlePointerDown = (e: React.PointerEvent) => {
    isDraggingRef.current = true;
    lastMousePosRef.current = { x: e.clientX, y: e.clientY };
  };

  const handlePointerMove = useCallback((e: React.PointerEvent) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    if (isDraggingRef.current) {
      const dx = e.clientX - lastMousePosRef.current.x;
      const dy = e.clientY - lastMousePosRef.current.y;
      rotYRef.current += dx * 0.005;
      rotXRef.current = Math.max(-0.65, Math.min(0.65, rotXRef.current + dy * 0.005));
      lastMousePosRef.current = { x: e.clientX, y: e.clientY };
    } else {
      // Gentle parallax deflection
      const cx = rect.width / 2;
      const cy = rect.height / 2;
      mouseOffsetRef.current = {
        x: ((mouseX - cx) / cx) * 0.0007,
        y: ((mouseY - cy) / cy) * 0.0004,
      };

      // Hit-test for hovering nodes
      let foundNode: ForensicNode | null = null;
      let foundPos: { x: number; y: number } | null = null;

      nodeScreenMapRef.current.forEach(({ x, y, z, node }) => {
        if (z > 0.05) {
          const dist = Math.hypot(mouseX - x, mouseY - y);
          if (dist < 20) {
            foundNode = node;
            foundPos = { x, y };
          }
        }
      });

      setHoveredNode(foundNode);
      setTooltipPos(foundPos);
    }
  }, []);

  const handlePointerUp = () => {
    isDraggingRef.current = false;
  };

  // Click on globe to trigger an expanding forensic radar pulse
  const handleClick = (e: React.MouseEvent) => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    // Check if clicked directly on a node
    let targetX = clickX;
    let targetY = clickY;
    let nodeLat = 0;
    let nodeLon = 0;

    nodeScreenMapRef.current.forEach(({ x, y, z, node }) => {
      if (z > 0.05 && Math.hypot(clickX - x, clickY - y) < 24) {
        targetX = x;
        targetY = y;
        nodeLat = node.lat;
        nodeLon = node.lon;
      }
    });

    const newPulse: ClickPulse = {
      id: Date.now() + Math.random(),
      x: targetX,
      y: targetY,
      lat: nodeLat,
      lon: nodeLon,
      radius: 4,
      maxRadius: 36,
      alpha: 1,
    };

    pulsesRef.current.push(newPulse);
    if (pulsesRef.current.length > 6) {
      pulsesRef.current.shift();
    }
  };

  // Main 3D Rendering Engine
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationId: number;
    let photonTimer = 0;
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    const resizeCanvas = () => {
      if (!canvas || !containerRef.current) return;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const rect = containerRef.current.getBoundingClientRect();
      const width = rect.width || 540;
      const height = rect.height || 540;

      canvas.width = width * dpr;
      canvas.height = height * dpr;
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;

      ctx.resetTransform?.();
      ctx.scale(dpr, dpr);
    };

    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);

    // 3D Spherical to Screen Orthographic Coordinate Transformation
    const project3D = (latDeg: number, lonDeg: number, radius: number, rotX: number, rotY: number) => {
      const phi = (90 - latDeg) * (Math.PI / 180);
      const theta = (lonDeg + 180) * (Math.PI / 180) + rotY;

      // Spherical coordinates
      const x0 = -radius * Math.sin(phi) * Math.cos(theta);
      const y0 = radius * Math.cos(phi);
      const z0 = radius * Math.sin(phi) * Math.sin(theta);

      // Pitch rotation around X axis
      const y1 = y0 * Math.cos(rotX) - z0 * Math.sin(rotX);
      const z1 = y0 * Math.sin(rotX) + z0 * Math.cos(rotX);

      return { x: x0, y: y1, z: z1 };
    };

    const render = () => {
      if (!canvas || !containerRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const width = rect.width || 540;
      const height = rect.height || 540;
      const cx = width / 2;
      const cy = height / 2;
      const globeRadius = Math.min(width, height) * 0.41;

      // Update rotation
      if (!prefersReducedMotion && !isDraggingRef.current) {
        rotYRef.current += baseSpeedRef.current + mouseOffsetRef.current.x;
        rotXRef.current += mouseOffsetRef.current.y * 0.4;
        rotXRef.current = Math.max(-0.55, Math.min(0.55, rotXRef.current));
      }

      photonTimer += 0.009;
      if (photonTimer > 1) photonTimer = 0;

      ctx.clearRect(0, 0, width, height);

      const rotX = rotXRef.current;
      const rotY = rotYRef.current;

      // 1. Subtle Atmospheric Outer Glow Halo
      const atmosphere = ctx.createRadialGradient(cx, cy, globeRadius * 0.6, cx, cy, globeRadius * 1.35);
      atmosphere.addColorStop(0, 'rgba(201, 173, 167, 0.05)');
      atmosphere.addColorStop(0.55, 'rgba(74, 125, 155, 0.04)');
      atmosphere.addColorStop(1, 'rgba(1, 23, 36, 0)');

      ctx.fillStyle = atmosphere;
      ctx.beginPath();
      ctx.arc(cx, cy, globeRadius * 1.35, 0, Math.PI * 2);
      ctx.fill();

      // 2. Dark Navy / Almost-Black Globe Sphere Body
      const bodyGrad = ctx.createRadialGradient(
        cx - globeRadius * 0.35,
        cy - globeRadius * 0.35,
        globeRadius * 0.1,
        cx,
        cy,
        globeRadius
      );
      bodyGrad.addColorStop(0, '#041726');
      bodyGrad.addColorStop(0.7, '#020F19');
      bodyGrad.addColorStop(1, '#010A12');

      ctx.fillStyle = bodyGrad;
      ctx.beginPath();
      ctx.arc(cx, cy, globeRadius, 0, Math.PI * 2);
      ctx.fill();

      // 3. Ultra-subtle 1px Outer Glass Rim
      ctx.strokeStyle = 'rgba(201, 173, 167, 0.12)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(cx, cy, globeRadius, 0, Math.PI * 2);
      ctx.stroke();

      // 4. Render Razor-Sharp Micro Continent Dot Surface (iPhone Minimalism)
      GLOBE_POINTS.forEach((pt) => {
        const p = project3D(pt.lat, pt.lon, globeRadius, rotX, rotY);
        if (p.z > 0) {
          const depthRatio = p.z / globeRadius;
          const sx = cx + p.x;
          const sy = cy - p.y;

          ctx.beginPath();
          const dotRadius = 0.82 + depthRatio * 0.28;
          ctx.arc(sx, sy, dotRadius, 0, Math.PI * 2);
          ctx.fillStyle = `rgba(242, 233, 228, ${(0.28 + depthRatio * 0.58).toFixed(2)})`;
          ctx.fill();
        }
      });

      // 5. Map Screen Positions for Investigation Nodes
      const screenMap = new Map<string, { x: number; y: number; z: number; node: ForensicNode }>();
      FORENSIC_NODES.forEach((node) => {
        const p = project3D(node.lat, node.lon, globeRadius, rotX, rotY);
        const sx = cx + p.x;
        const sy = cy - p.y;
        screenMap.set(node.id, { x: sx, y: sy, z: p.z, node });
      });
      nodeScreenMapRef.current = screenMap;

      // 6. Render Whisper-Thin Orbital Arcs & Smooth Signal Traveling Photons
      FORENSIC_ARCS.forEach((arc, arcIdx) => {
        const p1 = screenMap.get(arc.from);
        const p2 = screenMap.get(arc.to);
        if (!p1 || !p2) return;

        // Draw arc if either node is on the visible front hemisphere
        if (p1.z > -globeRadius * 0.25 || p2.z > -globeRadius * 0.25) {
          const steps = 40;
          ctx.beginPath();

          for (let s = 0; s <= steps; s++) {
            const t = s / steps;
            const intLat = p1.node.lat + (p2.node.lat - p1.node.lat) * t;
            let intLon = p1.node.lon + (p2.node.lon - p1.node.lon) * t;

            if (Math.abs(p2.node.lon - p1.node.lon) > 180) {
              intLon = p1.node.lon + ((p2.node.lon - p1.node.lon + 360) % 360) * t;
            }

            // Sleek aerodynamic altitude curvature hugging the sphere
            const alt = Math.sin(t * Math.PI) * (globeRadius * 0.065);
            const elevatedR = globeRadius + alt;
            const p = project3D(intLat, intLon, elevatedR, rotX, rotY);

            const sx = cx + p.x;
            const sy = cy - p.y;

            if (s === 0) ctx.moveTo(sx, sy);
            else ctx.lineTo(sx, sy);
          }

          ctx.strokeStyle = arc.color;
          ctx.lineWidth = 0.9;
          ctx.stroke();

          // Traveling Signal Packet (Photon Tracer)
          if (p1.z > 0 || p2.z > 0) {
            const t = (photonTimer * arc.speed + arcIdx * 0.33) % 1;
            const intLat = p1.node.lat + (p2.node.lat - p1.node.lat) * t;
            let intLon = p1.node.lon + (p2.node.lon - p1.node.lon) * t;
            if (Math.abs(p2.node.lon - p1.node.lon) > 180) {
              intLon = p1.node.lon + ((p2.node.lon - p1.node.lon + 360) % 360) * t;
            }

            const alt = Math.sin(t * Math.PI) * (globeRadius * 0.065);
            const pulsePt = project3D(intLat, intLon, globeRadius + alt, rotX, rotY);

            if (pulsePt.z > 0) {
              const px = cx + pulsePt.x;
              const py = cy - pulsePt.y;

              // Soft luminous aura
              const flare = ctx.createRadialGradient(px, py, 0, px, py, 5);
              flare.addColorStop(0, 'rgba(255, 255, 255, 0.95)');
              flare.addColorStop(0.4, 'rgba(201, 173, 167, 0.45)');
              flare.addColorStop(1, 'rgba(201, 173, 167, 0)');

              ctx.fillStyle = flare;
              ctx.beginPath();
              ctx.arc(px, py, 5, 0, Math.PI * 2);
              ctx.fill();

              // Solid photon core
              ctx.fillStyle = '#FFFFFF';
              ctx.beginPath();
              ctx.arc(px, py, 1.1, 0, Math.PI * 2);
              ctx.fill();
            }
          }
        }
      });

      // 7. Render Click Radar Pulses
      pulsesRef.current = pulsesRef.current
        .map((pulse) => {
          const nextRadius = pulse.radius + 0.75;
          const nextAlpha = Math.max(0, 1 - nextRadius / pulse.maxRadius);

          let px = pulse.x;
          let py = pulse.y;
          if (pulse.lat !== 0 || pulse.lon !== 0) {
            const proj = project3D(pulse.lat, pulse.lon, globeRadius, rotX, rotY);
            if (proj.z > 0) {
              px = cx + proj.x;
              py = cy - proj.y;
            }
          }

          if (nextAlpha > 0.05) {
            ctx.beginPath();
            ctx.arc(px, py, nextRadius, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(201, 173, 167, ${(nextAlpha * 0.75).toFixed(2)})`;
            ctx.lineWidth = 1.1;
            ctx.stroke();
          }

          return {
            ...pulse,
            radius: nextRadius,
            alpha: nextAlpha,
            x: px,
            y: py,
          };
        })
        .filter((p) => p.alpha > 0.05);

      // 8. Render Minimalist Investigation Nodes (No Raw Text Clutter)
      const currentHovered = hoveredNodeRef.current;
      screenMap.forEach(({ x, y, z, node }) => {
        if (z > 0.02) {
          const depthRatio = Math.max(0.2, z / globeRadius);
          const isHovered = currentHovered?.id === node.id;

          // Outer Soft Halo
          ctx.beginPath();
          ctx.arc(x, y, isHovered ? 10 : 6, 0, Math.PI * 2);
          ctx.strokeStyle = isHovered
            ? 'rgba(216, 195, 207, 0.95)'
            : `rgba(201, 173, 167, ${(0.25 * depthRatio).toFixed(2)})`;
          ctx.lineWidth = isHovered ? 1.2 : 0.75;
          ctx.stroke();

          // Ambient Glow Circle
          ctx.beginPath();
          ctx.arc(x, y, isHovered ? 6 : 3.5, 0, Math.PI * 2);
          ctx.fillStyle = isHovered
            ? 'rgba(201, 173, 167, 0.35)'
            : `rgba(201, 173, 167, ${(0.14 * depthRatio).toFixed(2)})`;
          ctx.fill();

          // Luminous Micro-Core Dot
          ctx.beginPath();
          ctx.arc(x, y, isHovered ? 3 : 2, 0, Math.PI * 2);
          ctx.fillStyle = isHovered ? '#FFFFFF' : '#E8D5CE';
          ctx.fill();
        }
      });

      animationId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('resize', resizeCanvas);
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className={`forensic-globe-wrapper ${className}`}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onPointerLeave={handlePointerUp}
      onClick={handleClick}
      aria-label="Interactive 3D Digital Forensics Globe"
    >
      <canvas ref={canvasRef} className="forensic-globe-canvas" />

      {/* Apple-Style Minimalist Forensic Node Tooltip */}
      {hoveredNode && tooltipPos && (
        <div
          className="forensic-node-tooltip"
          style={{
            left: `${tooltipPos.x + 14}px`,
            top: `${tooltipPos.y - 18}px`,
          }}
        >
          <div className="tooltip-header">
            <span className={`tooltip-status-dot ${hoveredNode.status}`} />
            <span className="tooltip-title">{hoveredNode.name}</span>
          </div>
          <div className="tooltip-details">
            <span className="tooltip-ip">{hoveredNode.ip}</span>
            <span className="tooltip-type">
              {hoveredNode.city}, {hoveredNode.country} · {hoveredNode.asn}
            </span>
          </div>
        </div>
      )}

    </div>
  );
};

export default ForensicGlobe;
