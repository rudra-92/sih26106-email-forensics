import React, { memo } from 'react';
import { Handle, Position, type NodeProps } from '@xyflow/react';
import {
  Globe,
  Mail,
  Server,
  Link2,
  Hash,
  Briefcase,
  Layers,
  Network,
  MapPin,
  ShieldCheck,
} from 'lucide-react';
import type { ForensicNode } from './graphTypes';

const ENTITY_CONFIG: Record<
  string,
  { label: string; accentColor: string; icon: React.ComponentType<{ size?: number; style?: React.CSSProperties }> }
> = {
  domain: { label: 'DOMAIN', accentColor: '#F97316', icon: Globe },
  email_address: { label: 'EMAIL', accentColor: '#2563EB', icon: Mail },
  email: { label: 'EMAIL ENTITY', accentColor: '#2563EB', icon: Mail },
  ip: { label: 'IP ADDRESS', accentColor: '#64748B', icon: Server },
  ip_address: { label: 'IP ADDRESS', accentColor: '#64748B', icon: Server },
  url: { label: 'URL', accentColor: '#0284C7', icon: Link2 },
  message_id: { label: 'MESSAGE ID', accentColor: '#64748B', icon: Hash },
  case: { label: 'CASE ROOT', accentColor: '#475569', icon: Briefcase },
  infrastructure: { label: 'INFRASTRUCTURE', accentColor: '#64748B', icon: Layers },
  asn: { label: 'ASN', accentColor: '#6366F1', icon: Network },
  country: { label: 'LOCATION', accentColor: '#059669', icon: MapPin },
};

function getEntityConfig(type: string) {
  const norm = type.toLowerCase();
  return (
    ENTITY_CONFIG[norm] || {
      label: type.toUpperCase(),
      accentColor: '#64748B',
      icon: Layers,
    }
  );
}

export const ForensicNodeComponent: React.FC<NodeProps<ForensicNode>> = memo((props) => {
  const { data, selected } = props;
  const config = getEntityConfig(data.entityType);
  const IconComponent = config.icon;

  const isMatched = data.isMatched;
  const isDimmed = data.isDimmed;
  const isReference = data.isReference;
  const isTrail = data.isInTrail;
  const isSelected = selected || data.isSelected;

  const isMono = ['domain', 'ip', 'ip_address', 'url', 'hash', 'message_id'].includes(
    data.entityType.toLowerCase()
  );

  return (
    <div
      className={`forensic-node ${isSelected ? 'is-selected' : ''} ${isTrail ? 'is-in-trail' : ''} ${
        isMatched ? 'is-matched' : ''
      } ${isDimmed ? 'is-dimmed' : ''} ${isReference ? 'is-reference' : ''}`}
      style={{
        borderLeftColor: isReference ? '#D97706' : config.accentColor,
      }}
    >
      <Handle
        type="target"
        position={Position.Top}
        className="forensic-handle"
      />

      <div className="forensic-node-header">
        <div
          className="forensic-node-type"
          style={{ color: isReference ? '#B45309' : config.accentColor }}
        >
          <IconComponent size={11} style={{ marginRight: '4px' }} />
          <span>{isReference ? 'PROTECTED BRAND' : config.label}</span>
        </div>
        {isReference && (
          <span className="forensic-node-tag tag-reference" title="Protected reference brand from lookalike analysis">
            <ShieldCheck size={9} style={{ marginRight: '2px' }} />
            REF
          </span>
        )}
      </div>

      <div
        className={`forensic-node-value ${isMono ? 'mono-text' : ''}`}
        title={data.canonicalValue}
      >
        {data.canonicalValue}
      </div>

      <Handle
        type="source"
        position={Position.Bottom}
        className="forensic-handle"
      />
    </div>
  );
});

ForensicNodeComponent.displayName = 'ForensicNodeComponent';
