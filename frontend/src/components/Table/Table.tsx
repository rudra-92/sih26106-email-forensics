import React from 'react';
import './Table.css';

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  width?: string;
  render?: (item: T, index: number) => React.ReactNode;
}

export interface TableProps<T> {
  columns: Column<T>[];
  data: T[];
  keyExtractor: (item: T, index: number) => string;
  onRowClick?: (item: T) => void;
  emptyMessage?: React.ReactNode;
  className?: string;
}

export function Table<T>({
  columns,
  data,
  keyExtractor,
  onRowClick,
  emptyMessage = 'No records found.',
  className = '',
}: TableProps<T>) {
  return (
    <div className={`table-container ${className}`}>
      <table className="data-table">
        <thead>
          <tr>
            {columns.map((col) => (
              <th key={col.key} style={col.width ? { width: col.width } : undefined}>
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="table-empty-cell">
                {emptyMessage}
              </td>
            </tr>
          ) : (
            data.map((item, idx) => (
              <tr
                key={keyExtractor(item, idx)}
                onClick={onRowClick ? () => onRowClick(item) : undefined}
                className={onRowClick ? 'table-row-clickable' : ''}
              >
                {columns.map((col) => (
                  <td key={col.key}>
                    {col.render
                      ? col.render(item, idx)
                      : String((item as Record<string, unknown>)[col.key] ?? '')}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
