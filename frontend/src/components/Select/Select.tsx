import React from 'react';
import './Select.css';

export interface SelectOption {
  value: string;
  label: string;
}

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  options: SelectOption[];
  error?: string;
}

export const Select: React.FC<SelectProps> = ({
  label,
  options,
  error,
  id,
  className = '',
  ...props
}) => {
  const selectId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined);

  return (
    <div className={`select-group ${error ? 'select-has-error' : ''} ${className}`}>
      {label && (
        <label htmlFor={selectId} className="select-label">
          {label}
        </label>
      )}
      <select id={selectId} className="select-control" {...props}>
        {options.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      {error && <span className="select-error-msg">{error}</span>}
    </div>
  );
};
