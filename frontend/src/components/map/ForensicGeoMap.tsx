import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Map as MapLibreMap, NavigationControl, Marker, Popup } from 'maplibre-gl';
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
const LIBERTY_STYLE_URL = 'https://tiles.openfreemap.org/styles/liberty';

// Runtime cartographic refinements to enhance OpenFreeMap Liberty contrast & readability
function applyLiveLayerRefinements(map: MapLibreMap) {
  try {
    // 1. Base land / background: warm light parchment tone
    if (map.getLayer('background')) {
      map.setPaintProperty('background', 'background-color', '#EDE8DF');
    }

    // 2. Relief: reduce raster-opacity to eliminate pale muddy wash
    if (map.getLayer('natural_earth')) {
      map.setPaintProperty('natural_earth', 'raster-opacity', [
        'interpolate',
        ['exponential', 1.5],
        ['zoom'],
        0, 0.25,
        4, 0.1,
        7, 0,
      ]);
    }

    // 3. Ocean / water: crisp marine blue for distinct separation
    if (map.getLayer('water')) {
      map.setPaintProperty('water', 'fill-color', '#8FB5EC');
    }

    // 4. Country borders: crisp dark slate
    if (map.getLayer('boundary_2')) {
      map.setPaintProperty('boundary_2', 'line-color', '#334155');
      map.setPaintProperty('boundary_2', 'line-opacity', [
        'interpolate',
        ['linear'],
        ['zoom'],
        0, 0.8,
        2, 0.9,
        5, 1.0,
      ]);
      map.setPaintProperty('boundary_2', 'line-width', [
        'interpolate',
        ['linear'],
        ['zoom'],
        1, 1.2,
        3, 1.8,
        6, 2.4,
        12, 3.5,
      ]);
    }

    if (map.getLayer('boundary_disputed')) {
      map.setPaintProperty('boundary_disputed', 'line-color', '#475569');
      map.setPaintProperty('boundary_disputed', 'line-opacity', 0.85);
      map.setPaintProperty('boundary_disputed', 'line-width', [
        'interpolate',
        ['linear'],
        ['zoom'],
        1, 1.0,
        4, 1.5,
        8, 2.0,
      ]);
    }

    // 5. Country labels - high contrast text & white halo
    if (map.getLayer('label_country_1')) {
      map.setPaintProperty('label_country_1', 'text-color', '#0F172A');
      map.setPaintProperty('label_country_1', 'text-halo-color', '#FFFFFF');
      map.setPaintProperty('label_country_1', 'text-halo-width', 2.2);
      map.setPaintProperty('label_country_1', 'text-halo-blur', 0.5);
      map.setLayoutProperty('label_country_1', 'text-size', [
        'interpolate',
        ['linear'],
        ['zoom'],
        1, 11,
        2, 13.5,
        4, 17.5,
        7, 22,
      ]);
    }

    if (map.getLayer('label_country_2')) {
      map.setPaintProperty('label_country_2', 'text-color', '#0F172A');
      map.setPaintProperty('label_country_2', 'text-halo-color', '#FFFFFF');
      map.setPaintProperty('label_country_2', 'text-halo-width', 2.0);
      map.setPaintProperty('label_country_2', 'text-halo-blur', 0.5);
      map.setLayoutProperty('label_country_2', 'text-size', [
        'interpolate',
        ['linear'],
        ['zoom'],
        1, 10,
        2, 12,
        4, 15.5,
        7, 20,
      ]);
    }

    if (map.getLayer('label_country_3')) {
      map.setPaintProperty('label_country_3', 'text-color', '#1E293B');
      map.setPaintProperty('label_country_3', 'text-halo-color', '#FFFFFF');
      map.setPaintProperty('label_country_3', 'text-halo-width', 1.8);
      map.setPaintProperty('label_country_3', 'text-halo-blur', 0.5);
    }

    if (map.getLayer('label_state')) {
      map.setPaintProperty('label_state', 'text-color', '#334155');
      map.setPaintProperty('label_state', 'text-halo-color', '#FFFFFF');
      map.setPaintProperty('label_state', 'text-halo-width', 1.6);
      map.setPaintProperty('label_state', 'text-halo-blur', 0.5);
    }

    if (map.getLayer('label_city_capital')) {
      map.setPaintProperty('label_city_capital', 'text-color', '#0F172A');
      map.setPaintProperty('label_city_capital', 'text-halo-color', '#FFFFFF');
      map.setPaintProperty('label_city_capital', 'text-halo-width', 1.8);
      map.setPaintProperty('label_city_capital', 'text-halo-blur', 0.5);
    }

    if (map.getLayer('label_city')) {
      map.setPaintProperty('label_city', 'text-color', '#0F172A');
      map.setPaintProperty('label_city', 'text-halo-color', '#FFFFFF');
      map.setPaintProperty('label_city', 'text-halo-width', 1.8);
      map.setPaintProperty('label_city', 'text-halo-blur', 0.5);
    }
  } catch (err) {
    console.warn('Cartographic layer refinement warning:', err);
  }
}

export const ForensicGeoMap: React.FC<ForensicGeoMapProps> = ({
  originData,
  isDocNet = false,
  hasPeer = false,
}) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<MapLibreMap | null>(null);
  const markersRef = useRef<Marker[]>([]);

  // Coordinates extraction
  const geoInfo = originData?.geolocation;
  const lat = typeof geoInfo?.latitude === 'number' ? geoInfo.latitude : null;
  const lng = typeof geoInfo?.longitude === 'number' ? geoInfo.longitude : null;
  const hasCoordinates = !isDocNet && lat !== null && lng !== null;

  const initialZoom = hasCoordinates ? 5.5 : DEFAULT_ZOOM;
  const [currentZoom, setCurrentZoom] = useState<number>(initialZoom);

  const isMapLoadedRef = useRef(false);

  const updateMarkerAndCamera = useCallback((map: MapLibreMap, isInitial = false) => {
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
    markerEl.title = 'Earliest Reliable Observed Peer';
    markerEl.innerHTML = `
      <div class="forensic-marker-pulse"></div>
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/>
        <circle cx="12" cy="10" r="3"/>
      </svg>
    `;

    // Construct Popup HTML strictly with available enrichment
    const peerIp = originData?.earliest_reliable_peer || '—';
    const locParts = [geoInfo?.city, geoInfo?.region, geoInfo?.country].filter(Boolean);
    const locStr = locParts.length > 0 ? locParts.join(', ') : 'Recorded';
    const asnInfo = originData?.asn || {};
    const asnStr = asnInfo.asn || asnInfo.autonomous_system_number || 'Recorded';
    const orgStr = asnInfo.organization || asnInfo.autonomous_system_organization || 'Unavailable';
    const dataset = geoInfo?.source_dataset || geoInfo?.dataset_name || 'DB-IP Lite';

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
    }).setHTML(popupHtml);

    const marker = new Marker({ element: markerEl })
      .setLngLat([lng!, lat!])
      .setPopup(popup)
      .addTo(map);

    markersRef.current.push(marker);

    // Auto-open popup on load
    popup.addTo(map);

    if (!isInitial) {
      // Fly smoothly to marker location when case changes
      map.flyTo({
        center: [lng!, lat!],
        zoom: 6,
        duration: 800,
        essential: true,
      });
    }
  }, [hasCoordinates, lat, lng, originData, isDocNet, geoInfo]);

  // Initialize MapLibre
  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Prevent duplicate map initialization
    if (mapInstanceRef.current) return;

    const initialCenter = hasCoordinates ? [lng!, lat!] as [number, number] : DEFAULT_CENTER;

    const map = new MapLibreMap({
      container: mapContainerRef.current,
      style: LIBERTY_STYLE_URL,
      center: initialCenter,
      zoom: initialZoom,
      attributionControl: { compact: true },
      minZoom: 1,
      maxZoom: 16,
    });

    map.addControl(new NavigationControl({ showCompass: true }), 'top-right');
    mapInstanceRef.current = map;
    (window as any).__forensicMap = map;

    // Apply cartographic refinements on map load
    map.on('load', () => {
      isMapLoadedRef.current = true;
      applyLiveLayerRefinements(map);
      updateMarkerAndCamera(map, true);
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
    if (!map || !isMapLoadedRef.current) return;
    updateMarkerAndCamera(map, false);
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
      });
    } else {
      map.flyTo({
        center: DEFAULT_CENTER,
        zoom: DEFAULT_ZOOM,
        duration: 500,
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
