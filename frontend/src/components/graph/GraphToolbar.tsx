import React from 'react';
import {
  Search,
  X,
  Maximize2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Filter,
  Tag,
  EyeOff,
} from 'lucide-react';
import type { GraphFilterState } from './graphTypes';

interface GraphToolbarProps {
  filters: GraphFilterState;
  onFilterChange: (filters: GraphFilterState) => void;
  availableEntityTypes: string[];
  availableRelationshipTypes: string[];
  availableSourceModules: string[];
  matchCount?: number;
  totalNodes: number;
  hasSelection: boolean;
  onFitView: () => void;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onReset: () => void;
  onClearSelection: () => void;
}

export const GraphToolbar: React.FC<GraphToolbarProps> = ({
  filters,
  onFilterChange,
  availableEntityTypes,
  availableRelationshipTypes,
  availableSourceModules,
  matchCount,
  totalNodes,
  hasSelection,
  onFitView,
  onZoomIn,
  onZoomOut,
  onReset,
  onClearSelection,
}) => {
  const isFiltered =
    Boolean(filters.searchQuery) ||
    Boolean(filters.entityType) ||
    Boolean(filters.relationshipType) ||
    Boolean(filters.sourceModule);

  const handleClearFilters = () => {
    onFilterChange({
      ...filters,
      searchQuery: '',
      entityType: '',
      relationshipType: '',
      sourceModule: '',
    });
    onReset();
  };

  const handleToggleLabels = () => {
    onFilterChange({
      ...filters,
      showEdgeLabels: !filters.showEdgeLabels,
    });
  };

  return (
    <div className="graph-toolbar">
      {/* Search Input */}
      <div className="graph-search-container">
        <Search size={13} className="graph-search-icon" />
        <input
          type="text"
          className="graph-search-input"
          placeholder="Search entities (domain, IP, email, hash...)"
          value={filters.searchQuery}
          onChange={(e) => onFilterChange({ ...filters, searchQuery: e.target.value })}
        />
        {filters.searchQuery && (
          <button
            type="button"
            className="graph-search-clear"
            onClick={() => onFilterChange({ ...filters, searchQuery: '' })}
            title="Clear search"
          >
            <X size={12} />
          </button>
        )}
      </div>

      {filters.searchQuery && matchCount !== undefined && (
        <span className="graph-match-indicator">
          {matchCount} of {totalNodes} matching
        </span>
      )}

      {/* Filter Dropdowns */}
      <div className="graph-filter-group">
        <div className="graph-filter-select-wrapper">
          <Filter size={11} className="graph-filter-icon" />
          <select
            className="graph-filter-select"
            value={filters.entityType}
            onChange={(e) => onFilterChange({ ...filters, entityType: e.target.value })}
            aria-label="Filter by Entity Type"
          >
            <option value="">All Entity Types</option>
            {availableEntityTypes.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </div>

        {availableRelationshipTypes.length > 0 && (
          <div className="graph-filter-select-wrapper">
            <select
              className="graph-filter-select"
              value={filters.relationshipType}
              onChange={(e) => onFilterChange({ ...filters, relationshipType: e.target.value })}
              aria-label="Filter by Relationship Type"
            >
              <option value="">All Relationships</option>
              {availableRelationshipTypes.map((relType) => (
                <option key={relType} value={relType}>
                  {relType}
                </option>
              ))}
            </select>
          </div>
        )}

        {availableSourceModules.length > 0 && (
          <div className="graph-filter-select-wrapper">
            <select
              className="graph-filter-select"
              value={filters.sourceModule}
              onChange={(e) => onFilterChange({ ...filters, sourceModule: e.target.value })}
              aria-label="Filter by Source Module"
            >
              <option value="">All Modules</option>
              {availableSourceModules.map((mod) => (
                <option key={mod} value={mod}>
                  {mod}
                </option>
              ))}
            </select>
          </div>
        )}

        {isFiltered && (
          <button
            type="button"
            className="graph-toolbar-btn btn-clear-filters"
            onClick={handleClearFilters}
            title="Reset all filters"
          >
            <RotateCcw size={12} />
            <span>Clear Filters</span>
          </button>
        )}
      </div>

      {/* View & Selection Actions Group */}
      <div className="graph-actions-group">
        {hasSelection && (
          <button
            type="button"
            className="graph-toolbar-btn btn-clear-selection"
            onClick={onClearSelection}
            title="Deselect active node/edge and reset trail"
          >
            <EyeOff size={12} />
            <span>Clear Selection</span>
          </button>
        )}

        <button
          type="button"
          className={`graph-toolbar-btn ${filters.showEdgeLabels ? 'btn-active' : ''}`}
          onClick={handleToggleLabels}
          title={filters.showEdgeLabels ? 'Hide relationship edge labels' : 'Show relationship edge labels'}
        >
          <Tag size={12} />
          <span>Labels</span>
        </button>

        <div className="graph-zoom-btn-group">
          <button
            type="button"
            className="graph-toolbar-btn btn-icon-only"
            onClick={onZoomIn}
            title="Zoom in"
            aria-label="Zoom in"
          >
            <ZoomIn size={12} />
          </button>
          <button
            type="button"
            className="graph-toolbar-btn btn-icon-only"
            onClick={onZoomOut}
            title="Zoom out"
            aria-label="Zoom out"
          >
            <ZoomOut size={12} />
          </button>
        </div>

        <button
          type="button"
          className="graph-toolbar-btn"
          onClick={onFitView}
          title="Fit view to graph"
        >
          <Maximize2 size={12} />
          <span>Fit Graph</span>
        </button>
      </div>
    </div>
  );
};
