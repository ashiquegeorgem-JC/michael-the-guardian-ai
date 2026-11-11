import React from 'react';
import { Shield, LucideIcon } from 'lucide-react';
import { Button } from './Button';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
  actionIcon?: React.ReactNode;
}

export function EmptyState({
  icon: Icon = Shield,
  title,
  description,
  actionLabel,
  onAction,
  actionIcon,
}: EmptyStateProps) {
  return (
    <div
      className="rounded-xl p-10 text-center flex flex-col items-center justify-center my-4 font-sans"
      style={{
        backgroundColor: '#0C1119',
        border: '1px dashed rgba(255, 255, 255, 0.1)',
      }}
    >
      <div
        className="w-12 h-12 rounded-lg flex items-center justify-center mb-3.5 text-[#3B82F6]"
        style={{
          backgroundColor: 'rgba(59, 130, 246, 0.08)',
          border: '1px solid rgba(59, 130, 246, 0.2)',
        }}
      >
        <Icon size={22} />
      </div>

      <h4 className="text-base font-semibold text-[#F5F7FA] tracking-tight">
        {title}
      </h4>

      <p className="text-sm text-[#A7B1C0] max-w-md mt-1 mb-5 leading-relaxed">
        {description}
      </p>

      {actionLabel && onAction && (
        <Button
          variant="primary"
          size="sm"
          onClick={onAction}
          leftIcon={actionIcon}
        >
          {actionLabel}
        </Button>
      )}
    </div>
  );
}
