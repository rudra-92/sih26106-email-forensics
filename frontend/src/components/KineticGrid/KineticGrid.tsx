import React, { useEffect, useRef } from 'react';
import './KineticGrid.css';

interface KineticGridProps {
  className?: string;
  entranceAnimation?: boolean;
}

interface Node {
  x: number;
  y: number;
  originX: number;
  originY: number;
  vx: number;
  vy: number;
  gridX: number;
  gridY: number;
  pulseOffset: number;
}

interface Shockwave {
  x: number;
  y: number;
  radius: number;
  maxRadius: number;
  speed: number;
  power: number;
  alpha: number;
}

interface Packet {
  startNode: Node;
  endNode: Node;
  progress: number;
  speed: number;
}

export const KineticGrid: React.FC<KineticGridProps> = ({ className, entranceAnimation = true }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const ctx = canvas.getContext('2d', { alpha: true });
    if (!ctx) return;

    // Check prefers-reduced-motion
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    let animationFrameId: number;
    let width = 0;
    let height = 0;
    let nodes: Node[] = [];
    let shockwaves: Shockwave[] = [];
    let packets: Packet[] = [];
    let isVisible = true;

    const entranceStartTime = performance.now();

    // Mouse state
    const mouse = {
      x: -1000,
      y: -1000,
      targetX: -1000,
      targetY: -1000,
      isHovering: false,
    };

    // Color constants tailored to darker #011724 palette with subtle, non-distracting glow
    const COLOR_LINE_BASE = 'rgba(74, 125, 155, 0.16)';   // Subtle cyber line
    const COLOR_LINE_ACTIVE = 'rgba(201, 173, 167, 0.55)'; // Controlled active glow
    const COLOR_NODE_BASE = 'rgba(140, 185, 215, 0.75)';   // Soft nodes
    const COLOR_NODE_ACCENT = '#FFFFFF';                   // Crisp active core
    const COLOR_PACKET = '#FFFFFF';                        // Packet pulse

    const initGrid = () => {
      const rect = container.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = rect.width;
      height = rect.height;

      canvas.width = Math.floor(width * dpr);
      canvas.height = Math.floor(height * dpr);
      ctx.resetTransform?.();
      ctx.scale(dpr, dpr);

      // Reduced grid density so the headline is the clear visual focus
      const isMobile = width < 768;
      const spacing = isMobile ? 64 : 54;

      const cols = Math.ceil(width / spacing) + 2;
      const rows = Math.ceil(height / spacing) + 2;
      const offsetX = (width - (cols - 1) * spacing) / 2;
      const offsetY = (height - (rows - 1) * spacing) / 2;

      nodes = [];
      for (let r = 0; r < rows; r++) {
        for (let c = 0; c < cols; c++) {
          const posX = offsetX + c * spacing;
          const posY = offsetY + r * spacing;
          nodes.push({
            x: posX,
            y: posY,
            originX: posX,
            originY: posY,
            vx: 0,
            vy: 0,
            gridX: c,
            gridY: r,
            pulseOffset: (c * 0.3 + r * 0.2) % (Math.PI * 2),
          });
        }
      }
    };

    initGrid();

    // Resize observer
    const resizeObserver = new ResizeObserver(() => {
      initGrid();
      if (prefersReducedMotion) {
        drawStaticFrame();
      }
    });
    resizeObserver.observe(container);

    // Intersection observer to stop loop when scrolled out
    const intersectionObserver = new IntersectionObserver((entries) => {
      isVisible = entries[0]?.isIntersecting ?? false;
      if (isVisible && !prefersReducedMotion) {
        lastTime = performance.now();
      }
    }, { threshold: 0.05 });
    intersectionObserver.observe(container);

    // Mouse & Touch interaction
    const handlePointerMove = (e: PointerEvent) => {
      const rect = container.getBoundingClientRect();
      mouse.targetX = e.clientX - rect.left;
      mouse.targetY = e.clientY - rect.top;
      mouse.isHovering = true;
    };

    const handlePointerLeave = () => {
      mouse.isHovering = false;
      mouse.targetX = -1000;
      mouse.targetY = -1000;
    };

    const handleClick = (e: MouseEvent) => {
      if (prefersReducedMotion) return;
      const rect = container.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const clickY = e.clientY - rect.top;

      shockwaves.push({
        x: clickX,
        y: clickY,
        radius: 0,
        maxRadius: Math.min(width, 420),
        speed: 5.5,
        power: 14,
        alpha: 0.65,
      });

      // Spawn subtle telemetry packet bursts on click
      if (nodes.length > 0 && packets.length < 12) {
        const nearbyNodes = nodes.filter((n) => {
          const d = Math.hypot(n.originX - clickX, n.originY - clickY);
          return d < 120;
        });

        if (nearbyNodes.length >= 2) {
          const start = nearbyNodes[Math.floor(Math.random() * nearbyNodes.length)];
          const target = nodes.find(
            (n) =>
              (Math.abs(n.gridX - start.gridX) === 1 && n.gridY === start.gridY) ||
              (Math.abs(n.gridY - start.gridY) === 1 && n.gridX === start.gridX)
          );
          if (target) {
            packets.push({
              startNode: start,
              endNode: target,
              progress: 0,
              speed: 0.03 + Math.random() * 0.02,
            });
          }
        }
      }
    };

    container.addEventListener('pointermove', handlePointerMove);
    container.addEventListener('pointerleave', handlePointerLeave);
    container.addEventListener('click', handleClick);

    // Render static grid for reduced motion users
    const drawStaticFrame = () => {
      ctx.clearRect(0, 0, width, height);

      // Draw horizontal & vertical segments
      ctx.strokeStyle = COLOR_LINE_BASE;
      ctx.lineWidth = 1;

      const colsMap = new Map<number, Node[]>();
      nodes.forEach((n) => {
        if (!colsMap.has(n.gridY)) colsMap.set(n.gridY, []);
        colsMap.get(n.gridY)!.push(n);
      });

      colsMap.forEach((rowNodes) => {
        rowNodes.sort((a, b) => a.gridX - b.gridX);
        for (let i = 0; i < rowNodes.length - 1; i++) {
          ctx.beginPath();
          ctx.moveTo(rowNodes[i].x, rowNodes[i].y);
          ctx.lineTo(rowNodes[i + 1].x, rowNodes[i + 1].y);
          ctx.stroke();
        }
      });

      // Draw nodes with glowing aura
      nodes.forEach((n) => {
        // Outer halo
        ctx.fillStyle = 'rgba(125, 195, 235, 0.4)';
        ctx.beginPath();
        ctx.arc(n.x, n.y, 3.4, 0, Math.PI * 2);
        ctx.fill();

        // Inner core
        ctx.fillStyle = COLOR_NODE_BASE;
        ctx.beginPath();
        ctx.arc(n.x, n.y, 1.8, 0, Math.PI * 2);
        ctx.fill();
      });
    };

    if (prefersReducedMotion) {
      drawStaticFrame();
      return () => {
        resizeObserver.disconnect();
        intersectionObserver.disconnect();
        container.removeEventListener('pointermove', handlePointerMove);
        container.removeEventListener('pointerleave', handlePointerLeave);
        container.removeEventListener('click', handleClick);
      };
    }

    // Animation loop parameters with 70% sensitivity and softened background dots
    const SPRING = 0.048;
    const DAMPING = 0.70; // 70% kinetic sensitivity
    const MOUSE_INFLUENCE_RADIUS = 200; // subtle, non-intrusive range
    const MOUSE_FORCE = 7.5; // 70% controlled force

    let lastTime = performance.now();
    let packetTimer = 0;

    const animate = (time: number) => {
      animationFrameId = requestAnimationFrame(animate);

      if (!isVisible) return;

      const dt = Math.min((time - lastTime) / 1000, 0.1);
      lastTime = time;

      const elapsed = (time - entranceStartTime) / 1000;
      const isConstructing = entranceAnimation && elapsed < 2.8;
      const isMobile = width < 768;

      // Dynamically get exact pixel center of the logo centerpiece element
      let centerX = width / 2;
      let centerY = isMobile ? height * 0.28 : height * 0.26;
      const logoEl = document.getElementById('sandesh-hero-center-logo');
      if (logoEl && container) {
        const lRect = logoEl.getBoundingClientRect();
        const cRect = container.getBoundingClientRect();
        if (lRect.width > 0 && lRect.height > 0) {
          centerX = lRect.left + lRect.width / 2 - cRect.left;
          centerY = lRect.top + lRect.height / 2 - cRect.top;
        }
      }

      // Smooth 70% mouse tracking
      if (mouse.isHovering) {
        mouse.x += (mouse.targetX - mouse.x) * 0.70;
        mouse.y += (mouse.targetY - mouse.y) * 0.70;
      } else {
        mouse.x = -1000;
        mouse.y = -1000;
      }

      // Update shockwaves
      for (let i = shockwaves.length - 1; i >= 0; i--) {
        const sw = shockwaves[i];
        sw.radius += sw.speed;
        sw.alpha = Math.max(0, 0.5 * (1 - sw.radius / sw.maxRadius));
        if (sw.radius >= sw.maxRadius || sw.alpha <= 0.01) {
          shockwaves.splice(i, 1);
        }
      }

      // Trigger one gentle settling shockwave when logo finishes constructing
      if (isConstructing && elapsed >= 2.05 && shockwaves.length === 0) {
        shockwaves.push({
          x: centerX,
          y: centerY,
          radius: 12,
          maxRadius: Math.min(width, 340),
          speed: 4.8,
          power: 9,
          alpha: 0.45,
        });
      }

      // Random telemetry packets along grid paths
      packetTimer += dt;
      if (packetTimer > 0.6 && packets.length < 6 && nodes.length > 0) {
        packetTimer = 0;
        const randomStart = nodes[Math.floor(Math.random() * nodes.length)];
        const neighbors = nodes.filter(
          (n) =>
            (Math.abs(n.gridX - randomStart.gridX) === 1 && n.gridY === randomStart.gridY) ||
            (Math.abs(n.gridY - randomStart.gridY) === 1 && n.gridX === randomStart.gridX)
        );
        if (neighbors.length > 0) {
          const randomEnd = neighbors[Math.floor(Math.random() * neighbors.length)];
          packets.push({
            startNode: randomStart,
            endNode: randomEnd,
            progress: 0,
            speed: 0.015 + Math.random() * 0.018,
          });
        }
      }

      // Update nodes physics with 70% sensitivity
      const nodeCount = nodes.length;
      for (let i = 0; i < nodeCount; i++) {
        const n = nodes[i];

        // 1. Spring force to origin
        const dx = n.originX - n.x;
        const dy = n.originY - n.y;
        const ax = dx * SPRING;
        const ay = dy * SPRING;

        n.vx = (n.vx + ax) * DAMPING;
        n.vy = (n.vy + ay) * DAMPING;

        // 2. 70% sensitivity Cursor repulsion
        if (mouse.isHovering) {
          const mdx = n.x - mouse.x;
          const mdy = n.y - mouse.y;
          const mdist = Math.hypot(mdx, mdy);
          if (mdist < MOUSE_INFLUENCE_RADIUS && mdist > 0.001) {
            const factor = Math.pow(1 - mdist / MOUSE_INFLUENCE_RADIUS, 1.2) * MOUSE_FORCE;
            n.vx += (mdx / mdist) * factor;
            n.vy += (mdy / mdist) * factor;
          }
        }

        // 3. Shockwave ripple impulse
        for (let s = 0; s < shockwaves.length; s++) {
          const sw = shockwaves[s];
          const sdx = n.x - sw.x;
          const sdy = n.y - sw.y;
          const sdist = Math.hypot(sdx, sdy);
          const diff = Math.abs(sdist - sw.radius);
          if (diff < 40 && sdist > 0.001) {
            const force = (1 - diff / 40) * sw.power * (1 - sw.radius / sw.maxRadius);
            n.vx += (sdx / sdist) * force * 0.15;
            n.vy += (sdy / sdist) * force * 0.15;
          }
        }

        // Apply velocities
        n.x += n.vx;
        n.y += n.vy;
      }

      // Render Scene
      ctx.clearRect(0, 0, width, height);

      // Subtle ambient cursor glow tailored to #011724
      if (mouse.isHovering && mouse.x > -500) {
        const glowGrad = ctx.createRadialGradient(
          mouse.x,
          mouse.y,
          0,
          mouse.x,
          mouse.y,
          200
        );
        glowGrad.addColorStop(0, 'rgba(201, 173, 167, 0.16)');
        glowGrad.addColorStop(0.4, 'rgba(74, 125, 155, 0.08)');
        glowGrad.addColorStop(1, 'rgba(1, 23, 36, 0)');
        ctx.fillStyle = glowGrad;
        ctx.beginPath();
        ctx.arc(mouse.x, mouse.y, 200, 0, Math.PI * 2);
        ctx.fill();
      }

      // Render shockwave ripple outlines
      for (let s = 0; s < shockwaves.length; s++) {
        const sw = shockwaves[s];
        ctx.strokeStyle = `rgba(201, 173, 167, ${sw.alpha * 0.4})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(sw.x, sw.y, sw.radius, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Render grid lines
      const lookup = new Map<string, Node>();
      for (let i = 0; i < nodeCount; i++) {
        lookup.set(`${nodes[i].gridX},${nodes[i].gridY}`, nodes[i]);
      }

      ctx.lineWidth = 1;
      for (let i = 0; i < nodeCount; i++) {
        const n = nodes[i];

        // Right neighbor
        const right = lookup.get(`${n.gridX + 1},${n.gridY}`);
        if (right) {
          const dist = Math.hypot(n.x - right.x, n.y - right.y);
          const strain = Math.abs(dist - Math.abs(n.originX - right.originX));
          const alpha = Math.min(0.45, 0.18 + strain * 0.04);
          ctx.strokeStyle = strain > 1.2 ? COLOR_LINE_ACTIVE : COLOR_LINE_BASE;
          ctx.globalAlpha = alpha;
          ctx.beginPath();
          ctx.moveTo(n.x, n.y);
          ctx.lineTo(right.x, right.y);
          ctx.stroke();
        }

        // Bottom neighbor
        const bottom = lookup.get(`${n.gridX},${n.gridY + 1}`);
        if (bottom) {
          const dist = Math.hypot(n.x - bottom.x, n.y - bottom.y);
          const strain = Math.abs(dist - Math.abs(n.originY - bottom.originY));
          const alpha = Math.min(0.45, 0.18 + strain * 0.04);
          ctx.strokeStyle = strain > 1.2 ? COLOR_LINE_ACTIVE : COLOR_LINE_BASE;
          ctx.globalAlpha = alpha;
          ctx.beginPath();
          ctx.moveTo(n.x, n.y);
          ctx.lineTo(bottom.x, bottom.y);
          ctx.stroke();
        }
      }

      ctx.globalAlpha = 1;

      // Render converging construction lines toward the exact logo centerpiece vertices
      if (isConstructing) {
        const settleFade = Math.max(0, 1 - Math.max(0, elapsed - 1.8) / 0.7);

        for (let i = 0; i < nodeCount; i++) {
          const n = nodes[i];
          const dist = Math.hypot(n.originX - centerX, n.originY - centerY);
          if (dist >= 60 && dist <= 320) {
            const angle = Math.atan2(n.originY - centerY, n.originX - centerX);
            const normAngle = (angle + Math.PI) / (Math.PI * 2);
            const delay = 0.10 + normAngle * 0.80;
            const lineProgress = Math.min(1, Math.max(0, (elapsed - (delay + 0.12)) / 0.75));

            if (lineProgress > 0 && settleFade > 0) {
              // Map angle to precise logo anchor vertex (crest, shoulders, flanks, anchor tip)
              let vertexOffsetX = Math.cos(angle) * 32;
              let vertexOffsetY = Math.sin(angle) * 32;

              // Snap to key anatomical anchor points
              const deg = (angle * 180) / Math.PI;
              if (deg > -115 && deg < -65) {
                // Top shield crest
                vertexOffsetX = 0;
                vertexOffsetY = -29;
              } else if (deg >= -65 && deg < -20) {
                // Right bridge node
                vertexOffsetX = 16;
                vertexOffsetY = -15;
              } else if (deg <= -115 && deg > -160) {
                // Left bridge node
                vertexOffsetX = -16;
                vertexOffsetY = -15;
              } else if (deg >= -20 && deg < 35) {
                // Right shield flank
                vertexOffsetX = 26;
                vertexOffsetY = 0;
              } else if (deg <= -160 || deg > 145) {
                // Left shield flank
                vertexOffsetX = -26;
                vertexOffsetY = 0;
              } else if (deg >= 65 && deg <= 115) {
                // Bottom anchor vertex
                vertexOffsetX = 0;
                vertexOffsetY = 28;
              }

              const targetX = centerX + vertexOffsetX;
              const targetY = centerY + vertexOffsetY;
              const curX = n.x + (targetX - n.x) * lineProgress;
              const curY = n.y + (targetY - n.y) * lineProgress;

              ctx.strokeStyle = `rgba(201, 173, 167, ${0.48 * settleFade * lineProgress})`;
              ctx.lineWidth = 1.1;
              ctx.beginPath();
              ctx.moveTo(n.x, n.y);
              ctx.lineTo(curX, curY);
              ctx.stroke();

              // Telemetry packet traveling along converging ray
              if (lineProgress > 0.12 && lineProgress < 0.98) {
                const packetFrac = ((elapsed * 2.5 + normAngle * 2) % 1);
                const px = n.x + (targetX - n.x) * (packetFrac * lineProgress);
                const py = n.y + (targetY - n.y) * (packetFrac * lineProgress);
                ctx.fillStyle = `rgba(255, 255, 255, ${0.85 * settleFade})`;
                ctx.beginPath();
                ctx.arc(px, py, 1.8, 0, Math.PI * 2);
                ctx.fill();
              }
            }
          }
        }
      }

      // Render packets
      for (let p = packets.length - 1; p >= 0; p--) {
        const pkt = packets[p];
        pkt.progress += pkt.speed;

        if (pkt.progress >= 1) {
          packets.splice(p, 1);
          continue;
        }

        const curX = pkt.startNode.x + (pkt.endNode.x - pkt.startNode.x) * pkt.progress;
        const curY = pkt.startNode.y + (pkt.endNode.y - pkt.startNode.y) * pkt.progress;

        ctx.fillStyle = COLOR_PACKET;
        ctx.beginPath();
        ctx.arc(curX, curY, 1.8, 0, Math.PI * 2);
        ctx.fill();
      }

      // Render Nodes with softened, subtle luminous halo
      for (let i = 0; i < nodeCount; i++) {
        const n = nodes[i];
        const disp = Math.hypot(n.x - n.originX, n.y - n.originY);
        const distToMouse = mouse.isHovering ? Math.hypot(n.x - mouse.x, n.y - mouse.y) : 9999;
        const proximity = Math.max(0, 1 - distToMouse / MOUSE_INFLUENCE_RADIUS);

        // Entrance node activation calculation
        let entranceGlow = 0;
        if (isConstructing) {
          const distToCenter = Math.hypot(n.originX - centerX, n.originY - centerY);
          if (distToCenter >= 70 && distToCenter <= 300) {
            const angle = Math.atan2(n.originY - centerY, n.originX - centerX);
            const normAngle = (angle + Math.PI) / (Math.PI * 2);
            const delay = 0.12 + normAngle * 0.85;
            if (elapsed > delay) {
              const settleFade = Math.max(0, 1 - Math.max(0, elapsed - 1.8) / 0.7);
              entranceGlow = Math.min(1, (elapsed - delay) / 0.4) * settleFade;
            }
          }
        }

        // 1. Softened outer glow halo
        const outerHaloRadius = Math.min(6.8, 2.6 + (proximity + entranceGlow * 0.7) * 3.6 + disp * 0.18);
        ctx.beginPath();
        ctx.arc(n.x, n.y, outerHaloRadius, 0, Math.PI * 2);
        if (proximity > 0.1 || entranceGlow > 0.2 || disp > 0.8) {
          ctx.fillStyle = `rgba(201, 173, 167, ${0.28 + (proximity + entranceGlow * 0.5) * 0.35})`;
        } else {
          ctx.fillStyle = 'rgba(90, 155, 195, 0.22)';
        }
        ctx.fill();

        // 2. Crisp core
        const coreRadius = Math.min(2.8, 1.4 + (proximity + entranceGlow * 0.5) * 0.9 + disp * 0.08);
        ctx.beginPath();
        ctx.arc(n.x, n.y, coreRadius, 0, Math.PI * 2);
        ctx.fillStyle = (proximity > 0.25 || entranceGlow > 0.4) ? COLOR_NODE_ACCENT : COLOR_NODE_BASE;
        ctx.fill();
      }
    };

    animationFrameId = requestAnimationFrame(animate);

    return () => {
      cancelAnimationFrame(animationFrameId);
      resizeObserver.disconnect();
      intersectionObserver.disconnect();
      container.removeEventListener('pointermove', handlePointerMove);
      container.removeEventListener('pointerleave', handlePointerLeave);
      container.removeEventListener('click', handleClick);
    };
  }, []);

  return (
    <div ref={containerRef} className={`kinetic-grid-container ${className || ''}`} aria-hidden="true">
      <canvas ref={canvasRef} className="kinetic-grid-canvas" />
    </div>
  );
};
