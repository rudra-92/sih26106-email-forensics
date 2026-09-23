import type { FC, CSSProperties, ReactNode } from 'react';
import { ArrowRight } from 'lucide-react';
import './MotionButton.css';

export interface MotionButtonProps {
  label: string;
  variant?: 'primary' | 'secondary';
  className?: string;
  animate?: boolean;
  delay?: number;
  icon?: ReactNode;
  onClick?: () => void;
}

export const MotionButton: FC<MotionButtonProps> = ({
  label,
  variant = 'primary',
  className = '',
  animate = true,
  delay = 0,
  icon,
  onClick,
}) => {
  return (
    <button
      type="button"
      className={`motion-button motion-button--${variant} ${className}`}
      style={{ '--motion-delay': `${delay}ms` } as CSSProperties}
      onClick={onClick}
    >
      <span
        className={`motion-button__circle ${
          animate ? 'motion-button__circle--animated' : ''
        }`}
        aria-hidden="true"
      />

      <span className="motion-button__icon" aria-hidden="true">
        {icon || <ArrowRight size={18} strokeWidth={2.2} />}
      </span>

      <span className="motion-button__text">
        {label}
      </span>
    </button>
  );
};

export default MotionButton;
