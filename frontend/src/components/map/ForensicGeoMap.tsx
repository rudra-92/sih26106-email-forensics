import React, { useEffect, useRef, useState, useCallback } from 'react';
import {
  Map as MapLibreMap,
  NavigationControl,
  Marker,
  Popup,
  type StyleSpecification,
} from 'maplibre-gl';
import 'maplibre-gl/dist/maplibre-gl.css';
import { Compass, Crosshair, AlertTriangle, Info, MapPin } from 'lucide-react';
import type { OriginData } from '../../types';
import './map.css';

interface ForensicGeoMapProps {
  originData: OriginData | null;
  caseId: string;
  isDocNet?: boolean;
  hasPeer?: boolean;
}

const DEFAULT_CENTER: [number, number] = [0, 20];
const DEFAULT_ZOOM = 1.3;

// Reliable publicly accessible OpenStreetMap tile layer (no API key required, crisp contrast)
const PUBLIC_MAP_STYLE: StyleSpecification = {
  version: 8,
  sources: {
    'osm-tiles': {
      type: 'raster',
      tiles: [
        'https://a.tile.openstreetmap.org/{z}/{x}/{y}.png',
        'https://b.tile.openstreetmap.org/{z}/{x}/{y}.png',
        'https://c.tile.openstreetmap.org/{z}/{x}/{y}.png',
      ],
      tileSize: 256,
      attribution:
        '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a> contributors',
    },
  },
  layers: [
    {
      id: 'osm-tiles-layer',
      type: 'raster',
      source: 'osm-tiles',
      minzoom: 0,
      maxzoom: 19,
    },
  ],
};

export const ForensicGeoMap: React.FC<ForensicGeoMapProps> = ({
  originData,
  isDocNet = false,
  hasPeer = false,
}) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<MapLibreMap | null>(null);
  const markersRef = useRef<Marker[]>([]);
  const isMapLoadedRef = useRef(false);

  // Coordinates extraction safely handling missing/null/NaN values
  const geoInfo = (originData?.geolocation || {}) as Record<string, any>;
  const rawLat = geoInfo?.latitude;
  const rawLng = geoInfo?.longitude;
  const lat = typeof rawLat === 'number' && !isNaN(rawLat) ? rawLat : null;
  const lng = typeof rawLng === 'number' && !isNaN(rawLng) ? rawLng : null;
  const hasCoordinates = !isDocNet && lat !== null && lng !== null;

  const initialZoom = hasCoordinates ? 5.5 : DEFAULT_ZOOM;
  const [currentZoom, setCurrentZoom] = useState<number>(initialZoom);

  // Preserve city, state, and country names
  const peerIp = originData?.earliest_reliable_peer || '—';
  const cityName = geoInfo?.city;
  const stateName = geoInfo?.region || geoInfo?.state || geoInfo?.subdivision;
  const countryName = geoInfo?.country || geoInfo?.country_name;
  const locParts = [cityName, stateName, countryName].filter(Boolean);
  const locStr = locParts.length > 0 ? locParts.join(', ') : 'Recorded';

  const asnInfo = (originData?.asn || {}) as Record<string, any>;
  const asnStr = asnInfo.asn || asnInfo.autonomous_system_number || 'Recorded';
  const orgStr = asnInfo.organization || asnInfo.autonomous_system_organization || 'Unavailable';
  const dataset = geoInfo?.source_dataset || geoInfo?.dataset_name || 'DB-IP Lite';

  const updateMarkerAndCamera = useCallback(
    (map: MapLibreMap, isInitial = false) => {
      // Clear existing markers
      markersRef.current.forEach((m) => m.remove());
      markersRef.current = [];

      if (!hasCoordinates) {
        if (!isInitial) {
          map.flyTo({ center: DEFAULT_CENTER, zoom: DEFAULT_ZOOM, duration: 600 });
        }
        return;
      }

      // Create custom DOM Marker for Earliest Reliable Peer
      const markerEl = document.createElement('div');
      markerEl.className = 'forensic-marker';
      markerEl.title = `Earliest Reliable Observed Peer: ${peerIp}`;
      markerEl.innerHTML = `
        <div class="forensic-marker-pulse"></div>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/>
          <circle cx="12" cy="10" r="3"/>
        </svg>
      `;

      // Construct Popup HTML strictly with available enrichment
      const popupHtml = `
        <div class="map-popup-header">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <rect width="20" height="8" x="2" y="2" rx="2" ry="2"/>
            <rect width="20" height="8" x="2" y="14" rx="2" ry="2"/>
          </svg>
          EARLIEST RELIABLE OBSERVED PEER
        </div>
        <div class="map-popup-ip">${peerIp}</div>
        <div class="map-popup-grid">
          <div class="map-popup-row">
            <span class="map-popup-label">Location:</span>
            <span class="map-popup-val">${locStr}</span>
          </div>
          <div class="map-popup-row">
            <span class="map-popup-label">ASN:</span>
            <span class="map-popup-val">${asnStr}</span>
          </div>
          <div class="map-popup-row">
            <span class="map-popup-label">Operator:</span>
            <span class="map-popup-val">${orgStr}</span>
          </div>
          <div class="map-popup-row">
            <span class="map-popup-label">Dataset:</span>
            <span class="map-popup-val">${dataset}</span>
          </div>
        </div>
        <div class="map-popup-disclaimer">
          Routing Point-of-Presence (PoP) observation from received headers. NOT physical person location.
        </div>
      `;

      const popup = new Popup({
        offset: 24,
        closeButton: true,
        closeOnClick: false,
        maxWidth: '320px',
      })
        .setLngLat([lng!, lat!])
        .setHTML(popupHtml);

      const marker = new Marker({ element: markerEl, anchor: 'center' })
        .setLngLat([lng!, lat!])
        .setPopup(popup)
        .addTo(map);

      markersRef.current.push(marker);

      // Open popup on marker
      marker.togglePopup();

      if (!isInitial) {
        map.flyTo({
          center: [lng!, lat!],
          zoom: 6,
          duration: 800,
          essential: true,
        });
      }
    },
    [hasCoordinates, lat, lng, originData, isDocNet, geoInfo, peerIp, locStr, asnStr, orgStr, dataset]
  );

  // Keep latest updateMarkerAndCamera callback in ref to prevent stale closures
  const updateMarkerAndCameraRef = useRef(updateMarkerAndCamera);
  useEffect(() => {
    updateMarkerAndCameraRef.current = updateMarkerAndCamera;
  }, [updateMarkerAndCamera]);

  // Initialize MapLibre
  useEffect(() => {
    if (!mapContainerRef.current) return;
    if (mapInstanceRef.current) return;

    const initialCenter = hasCoordinates ? ([lng!, lat!] as [number, number]) : DEFAULT_CENTER;

    const map = new MapLibreMap({
      container: mapContainerRef.current,
      style: PUBLIC_MAP_STYLE,
      center: initialCenter,
      zoom: initialZoom,
      attributionControl: { compact: true },
      minZoom: 1,
      maxZoom: 18,
    });

    map.addControl(new NavigationControl({ showCompass: true }), 'top-right');
    mapInstanceRef.current = map;
    (window as any).__forensicMap = map;

    // Apply markers and camera on map load
    map.on('load', () => {
      isMapLoadedRef.current = true;
      map.resize();
      updateMarkerAndCameraRef.current(map, true);
    });

    map.on('zoom', () => {
      setCurrentZoom(map.getZoom());
    });

    // Responsive container observation
    const resizeObserver = new ResizeObserver(() => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.resize();
      }
    });
    resizeObserver.observe(mapContainerRef.current);

    return () => {
      resizeObserver.disconnect();
      markersRef.current.forEach((m) => m.remove());
      markersRef.current = [];
      map.remove();
      mapInstanceRef.current = null;
      isMapLoadedRef.current = false;
    };
  }, []); // Run once on mount

  // Update Markers and Camera when originData changes after initial map load
  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;
    if (isMapLoadedRef.current || map.isStyleLoaded()) {
      updateMarkerAndCamera(map, false);
    }
  }, [updateMarkerAndCamera]);

  // Controls Handlers
  const handleFitObservations = useCallback(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    if (hasCoordinates) {
      map.flyTo({
        center: [lng!, lat!],
        zoom: 6,
        duration: 500,
        essential: true,
      });
    } else {
      map.flyTo({
        center: DEFAULT_CENTER,
        zoom: DEFAULT_ZOOM,
        duration: 500,
        essential: true,
      });
    }
  }, [hasCoordinates, lat, lng]);

  const handleResetView = useCallback(() => {
    const map = mapInstanceRef.current;
    if (!map) return;
    map.flyTo({
      center: DEFAULT_CENTER,
      zoom: DEFAULT_ZOOM,
      bearing: 0,
      pitch: 0,
      duration: 500,
      essential: true,
    });
  }, []);

  return (
    <div className="forensic-map-wrapper">
      {/* MapLibre WebGL Canvas Container */}
      <div ref={mapContainerRef} className="forensic-map-canvas" />

      {/* Map Action Toolbar */}
      <div className="forensic-map-toolbar">
        <button
          type="button"
          className="forensic-map-btn"
          onClick={handleFitObservations}
          title="Center on observed infrastructure"
        >
          <Crosshair size={12} />
          <span>Fit Observations</span>
        </button>
        <button
          type="button"
          className="forensic-map-btn"
          onClick={handleResetView}
          title="Reset to world overview"
        >
          <Compass size={12} />
          <span>Reset View</span>
        </button>
        <div className="forensic-map-zoom-badge" title="Current Map Zoom Level">
          <span>Zoom {currentZoom.toFixed(1)}</span>
        </div>
      </div>

      {/* Case-specific Status Overlays */}
      {isDocNet && (
        <div className="forensic-map-overlay-banner banner-synthetic">
          <div className="forensic-map-banner-title">
            <AlertTriangle size={14} style={{ color: '#D97706' }} />
            <span>Documentation / Synthetic Network (RFC 5737)</span>
          </div>
          <p className="forensic-map-banner-desc">
            The observed peer IP (<code className="mono-text">{originData?.earliest_reliable_peer}</code>) belongs to a designated RFC 5737 documentation test block. It represents synthetic laboratory infrastructure and carries no real-world physical or PoP geolocation.
          </p>
        </div>
      )}

      {!hasPeer && (
        <div className="forensic-map-overlay-banner banner-empty">
          <div className="forensic-map-banner-title">
            <Info size={14} style={{ color: '#64748B' }} />
            <span>No Geolocatable Infrastructure Available</span>
          </div>
          <p className="forensic-map-banner-desc">
            No valid Received headers containing a routable sending peer were extracted from this email artifact. The base map is displayed in a neutral reference state without fabricated coordinates.
          </p>
        </div>
      )}

      {hasPeer && !isDocNet && !hasCoordinates && (
        <div className="forensic-map-overlay-banner banner-empty">
          <div className="forensic-map-banner-title">
            <MapPin size={14} style={{ color: '#64748B' }} />
            <span>Observed Peer Lacks Geographic Coordinates</span>
          </div>
          <p className="forensic-map-banner-desc">
            Peer IP <code className="mono-text">{originData?.earliest_reliable_peer}</code> was identified, but city/point coordinates were not present in the local MaxMind / DB-IP database.
          </p>
        </div>
      )}
    </div>
  );
};
