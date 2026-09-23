import React, { useEffect, useState, useMemo } from 'react';
import { FileSearch, ArrowUpDown } from 'lucide-react';
import {
  Panel,
  Table,
  Badge,
  LoadingState,
  EmptyState,
} from '../../../components';
import type { Column } from '../../../components';
import { fetchCaseEvidence } from '../../../api/cases';
import type { EvidenceItem } from '../../../types';
import { useCaseWorkspace } from '../CaseWorkspaceContext';
import { EvidenceDetailDrawer } from './EvidenceDetailDrawer';

type SortField = 'evidence_id' | 'source_module' | 'rule_id' | 'severity' | 'timestamp';
type SortOrder = 'asc' | 'desc';

export const EvidenceSection: React.FC = () => {
  const { caseId, caseData } = useCaseWorkspace();

  const [evidenceList, setEvidenceList] = useState<EvidenceItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceItem | null>(null);

  // Filters
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [moduleFilter, setModuleFilter] = useState<string>('all');
  const [trustFilter, setTrustFilter] = useState<string>('all');

  // Sorting
  const [sortField, setSortField] = useState<SortField>('evidence_id');
  const [sortOrder, setSortOrder] = useState<SortOrder>('asc');

  useEffect(() => {
    let isMounted = true;
    async function loadEvidence() {
      if (caseData.analysis_status !== 'completed') {
        setIsLoading(false);
        return;
      }

      setIsLoading(true);
      try {
        const res = await fetchCaseEvidence(caseId);
        if (isMounted) {
          setEvidenceList(res.evidence || []);
        }
      } catch {
        if (isMounted) setEvidenceList([]);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    loadEvidence();
    return () => {
      isMounted = false;
    };
  }, [caseId, caseData.analysis_status]);

  // Unique lists for dropdowns
  const availableModules = useMemo(() => {
    const mods = new Set<string>();
    evidenceList.forEach((e) => {
      if (e.source_module) mods.add(e.source_module);
    });
    return Array.from(mods).sort();
  }, [evidenceList]);

  const availableTrustStates = useMemo(() => {
    const trusts = new Set<string>();
    evidenceList.forEach((e) => {
      if (e.trust_state) trusts.add(e.trust_state);
    });
    return Array.from(trusts).sort();
  }, [evidenceList]);

  // Filter & Sort
  const filteredAndSortedEvidence = useMemo(() => {
    const result = evidenceList.filter((item) => {
      // Text search
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        const matchesId = item.evidence_id.toLowerCase().includes(q);
        const matchesRule = item.rule_id.toLowerCase().includes(q);
        const matchesDesc = item.description.toLowerCase().includes(q);
        if (!matchesId && !matchesRule && !matchesDesc) return false;
      }

      // Severity filter
      if (severityFilter !== 'all') {
        if (item.severity.toLowerCase() !== severityFilter.toLowerCase()) return false;
      }

      // Module filter
      if (moduleFilter !== 'all') {
        if (item.source_module !== moduleFilter) return false;
      }

      // Trust filter
      if (trustFilter !== 'all') {
        if (item.trust_state !== trustFilter) return false;
      }

      return true;
    });

    // Sorting
    result.sort((a, b) => {
      let valA = a[sortField] || '';
      let valB = b[sortField] || '';

      if (sortField === 'severity') {
        const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        valA = String(rank[a.severity.toLowerCase()] ?? -1);
        valB = String(rank[b.severity.toLowerCase()] ?? -1);
      }

      const cmp = String(valA).localeCompare(String(valB), undefined, { numeric: true });
      return sortOrder === 'asc' ? cmp : -cmp;
    });

    return result;
  }, [evidenceList, searchTerm, severityFilter, moduleFilter, trustFilter, sortField, sortOrder]);

  const handleSortToggle = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('asc');
    }
  };

  const getSeverityBadgeVariant = (sev: string): 'danger' | 'warning' | 'neutral' => {
    const s = sev.toLowerCase();
    if (s === 'critical' || s === 'high') return 'danger';
    if (s === 'medium') return 'warning';
    return 'neutral';
  };

  const columns: Column<EvidenceItem>[] = [
    {
      key: 'evidence_id',
      header: (
        <button
          onClick={() => handleSortToggle('evidence_id')}
          style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', font: 'inherit', color: 'inherit' }}
        >
          <span>Evidence ID</span>
          <ArrowUpDown size={12} />
        </button>
      ),
      width: '130px',
      render: (item) => (
        <span className="mono-text" style={{ fontWeight: 600, fontSize: '11px', color: 'var(--action-primary)' }}>
          {item.evidence_id}
        </span>
      ),
    },
    {
      key: 'source_module',
      header: (
        <button
          onClick={() => handleSortToggle('source_module')}
          style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', font: 'inherit', color: 'inherit' }}
        >
          <span>Source Module</span>
          <ArrowUpDown size={12} />
        </button>
      ),
      width: '160px',
      render: (item) => (
        <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
          {item.source_module}
        </span>
      ),
    },
    {
      key: 'rule_id',
      header: (
        <button
          onClick={() => handleSortToggle('rule_id')}
          style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', font: 'inherit', color: 'inherit' }}
        >
          <span>Rule ID / Category</span>
          <ArrowUpDown size={12} />
        </button>
      ),
      width: '190px',
      render: (item) => (
        <span className="mono-text" style={{ fontSize: '11px', fontWeight: 600 }}>
          {item.rule_id}
        </span>
      ),
    },
    {
      key: 'severity',
      header: (
        <button
          onClick={() => handleSortToggle('severity')}
          style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', font: 'inherit', color: 'inherit' }}
        >
          <span>Severity</span>
          <ArrowUpDown size={12} />
        </button>
      ),
      width: '90px',
      render: (item) => (
        <Badge variant={getSeverityBadgeVariant(item.severity)}>
          {item.severity.toUpperCase()}
        </Badge>
      ),
    },
    {
      key: 'trust_state',
      header: 'Trust State',
      width: '95px',
      render: (item) => (
        <Badge variant="neutral">{item.trust_state}</Badge>
      ),
    },
    {
      key: 'description',
      header: 'Description',
      render: (item) => (
        <span style={{ fontSize: '11px', color: 'var(--text-secondary)', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
          {item.description}
        </span>
      ),
    },
    {
      key: 'timestamp',
      header: 'Timestamp',
      width: '120px',
      render: (item) => (
        <span className="mono-text" style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
          {item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '—'}
        </span>
      ),
    },
  ];

  if (caseData.analysis_status !== 'completed') {
    return (
      <Panel title="Forensic Evidence" subtitle="Normalized evidence records from forensic modules">
        <EmptyState
          title="Analysis Not Run"
          description="Forensic evidence items will appear here once analysis pipeline execution completes."
        />
      </Panel>
    );
  }

  if (isLoading) {
    return <LoadingState label="Loading normalized forensic evidence items..." />;
  }

  return (
    <div className="case-workspace-body evidence-section-container">
      {/* Evidence Filter & Search Toolbar */}
      <div className="evidence-toolbar">
        <div className="evidence-filters">
          <input
            type="text"
            className="evidence-search-input"
            placeholder="Search by ID, rule, or description..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />

          <select
            className="evidence-filter-select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          {availableModules.length > 0 && (
            <select
              className="evidence-filter-select"
              value={moduleFilter}
              onChange={(e) => setModuleFilter(e.target.value)}
            >
              <option value="all">All Modules</option>
              {availableModules.map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          )}

          {availableTrustStates.length > 0 && (
            <select
              className="evidence-filter-select"
              value={trustFilter}
              onChange={(e) => setTrustFilter(e.target.value)}
            >
              <option value="all">All Trust States</option>
              {availableTrustStates.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          )}
        </div>

        <div style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          Showing <strong>{filteredAndSortedEvidence.length}</strong> of <strong>{evidenceList.length}</strong> items
        </div>
      </div>

      {/* Table & Slideout Split */}
      <div className="evidence-workspace-split">
        <div className="evidence-table-main">
          <Table<EvidenceItem>
            columns={columns}
            data={filteredAndSortedEvidence}
            keyExtractor={(item) => item.evidence_id}
            onRowClick={(item) => setSelectedEvidence(item)}
            emptyMessage={
              <EmptyState
                icon={<FileSearch size={20} />}
                title="No Evidence Matches Filter"
                description="Try clearing search filters to see all evidence items."
              />
            }
          />
        </div>

        {/* Selected Evidence Detail Slideout Drawer */}
        {selectedEvidence && (
          <EvidenceDetailDrawer
            evidence={selectedEvidence}
            onClose={() => setSelectedEvidence(null)}
          />
        )}
      </div>
    </div>
  );
};
