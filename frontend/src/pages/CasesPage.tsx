import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, RefreshCw, FolderLock, ExternalLink } from 'lucide-react';
import {
  SectionHeader,
  Button,
  Table,
  EmptyState,
  LoadingState,
  ErrorState,
  StatusBadge,
  Modal,
  Input,
  type Column,
} from '../components';
import { fetchCases, createCase, formatCaseError } from '../api/cases';
import type { Case } from '../types';

export const CasesPage: React.FC = () => {
  const navigate = useNavigate();
  const [cases, setCases] = useState<Case[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // New Case Modal State
  const [isModalOpen, setIsModalOpen] = useState<boolean>(false);
  const [newTitle, setNewTitle] = useState<string>('');
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [formError, setFormError] = useState<string>('');

  const loadCases = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await fetchCases();
      setCases(data.cases || []);
    } catch (err: unknown) {
      setError(formatCaseError(err));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, []);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      setFormError('Case title is required.');
      return;
    }

    setIsSubmitting(true);
    setFormError('');
    try {
      const newCase = await createCase({ title: newTitle.trim() });
      setNewTitle('');
      setIsModalOpen(false);
      await loadCases();
      navigate(`/cases/${newCase.case_id}`);
    } catch (err: unknown) {
      setFormError(formatCaseError(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  const columns: Column<Case>[] = [
    {
      key: 'case_id',
      header: 'Case ID',
      width: '180px',
      render: (c) => (
        <span className="mono-text" style={{ fontWeight: 600, color: 'var(--action-primary)' }}>
          {c.case_id}
        </span>
      ),
    },
    {
      key: 'title',
      header: 'Title',
      render: (c) => <strong>{c.title}</strong>,
    },
    {
      key: 'status',
      header: 'Status',
      width: '110px',
      render: (c) => <StatusBadge status={c.status} type="case" />,
    },
    {
      key: 'analysis_status',
      header: 'Analysis Status',
      width: '140px',
      render: (c) => <StatusBadge status={c.analysis_status} type="analysis" />,
    },
    {
      key: 'threat_label',
      header: 'Threat',
      width: '140px',
      render: (c) =>
        c.threat_label ? (
          <StatusBadge status={c.threat_label} type="threat" />
        ) : (
          <span style={{ color: 'var(--text-dim)', fontSize: 'var(--text-xs)' }}>
            Unassessed
          </span>
        ),
    },
    {
      key: 'threat_confidence',
      header: 'Confidence',
      width: '120px',
      render: (c) =>
        c.threat_confidence != null ? (
          <span className="mono-text" style={{ fontWeight: 500 }}>
            {(c.threat_confidence * 100).toFixed(2)}%
          </span>
        ) : (
          <span style={{ color: 'var(--text-dim)', fontSize: 'var(--text-xs)' }}>
            —
          </span>
        ),
    },
    {
      key: 'created_at',
      header: 'Created',
      width: '150px',
      render: (c) => (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {new Date(c.created_at).toLocaleString()}
        </span>
      ),
    },
    {
      key: 'updated_at',
      header: 'Updated',
      width: '150px',
      render: (c) => (
        <span style={{ fontSize: 'var(--text-xs)', color: 'var(--text-muted)' }}>
          {new Date(c.updated_at).toLocaleString()}
        </span>
      ),
    },
    {
      key: 'actions',
      header: 'Actions',
      width: '100px',
      render: (c) => (
        <Button
          variant="outline"
          size="sm"
          icon={<ExternalLink size={12} />}
          onClick={(e) => {
            e.stopPropagation();
            navigate(`/cases/${c.case_id}`);
          }}
        >
          Open
        </Button>
      ),
    },
  ];

  return (
    <div>
      <SectionHeader
        title="Case Management"
        description="Forensic investigation containers, evidence tracking, and origin attribution records."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              icon={<RefreshCw size={14} />}
              onClick={loadCases}
              disabled={isLoading}
            >
              Refresh
            </Button>
            <Button
              variant="primary"
              size="sm"
              icon={<Plus size={14} />}
              onClick={() => setIsModalOpen(true)}
            >
              Create Investigation
            </Button>
          </>
        }
      />

      {isLoading && <LoadingState label="Loading cases from repository..." />}

      {error && (
        <ErrorState
          title="Investigation Registry Notice"
          message={error}
          onRetry={loadCases}
        />
      )}

      {!isLoading && !error && cases.length === 0 && (
        <EmptyState
          icon={<FolderLock size={24} />}
          title="No investigations yet."
          description="Create your first forensic case to begin ingesting .eml artifacts, extracting entities, and running the analysis pipeline."
          action={
            <Button
              variant="primary"
              size="sm"
              icon={<Plus size={14} />}
              onClick={() => setIsModalOpen(true)}
            >
              Create Investigation
            </Button>
          }
        />
      )}

      {!isLoading && !error && cases.length > 0 && (
        <Table<Case>
          columns={columns}
          data={cases}
          keyExtractor={(item) => item.case_id}
          onRowClick={(item) => navigate(`/cases/${item.case_id}`)}
        />
      )}

      {/* Modal for creating a new investigation case */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Create Investigation Case"
        footer={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIsModalOpen(false)}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              size="sm"
              onClick={handleCreateCase}
              isLoading={isSubmitting}
            >
              Create Investigation
            </Button>
          </>
        }
      >
        <form onSubmit={handleCreateCase}>
          <Input
            label="Case Title / Subject"
            placeholder="e.g. Finance Spear Phishing - Incident #2026-09"
            value={newTitle}
            onChange={(e) => setNewTitle(e.target.value)}
            error={formError}
            autoFocus
          />
        </form>
      </Modal>
    </div>
  );
};
