import React from 'react';
import { cn } from '@/lib/utils';

interface PanelProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: React.ReactNode;
  description?: React.ReactNode;
  icon?: React.ComponentType<{ size?: number; className?: string; color?: string }>;
  badge?: React.ReactNode;
  actions?: React.ReactNode;
  children: React.ReactNode;
  elevated?: boolean;
  noPadding?: boolean;
}

export function Panel({
  title,
  description,
  icon: Icon,
  badge,
  actions,
  children,
  elevated = false,
  noPadding = false,
  className,
  style,
  ...props
}: PanelProps) {
  const hasHeader = title || description || actions || badge || Icon;

  return (
    <div
      className={cn(
        'rounded-xl border transition-all duration-150 font-sans',
        elevated ? 'bg-[#222C35]' : 'bg-[#1C242B]',
        className
      )}
      style={{
        backgroundColor: elevated ? '#222C35' : '#1C242B',
        border: '1px solid rgba(212, 175, 55, 0.14)',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.4)',
        ...style,
      }}
      {...props}
    >
      {hasHeader && (
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4 border-b border-[rgba(212,175,55,0.1)]">
          <div className="flex items-center gap-2.5">
            {Icon && (
              <div className="w-7 h-7 rounded-lg bg-[rgba(212,175,55,0.1)] border border-[rgba(212,175,55,0.25)] flex items-center justify-center text-[#D4AF37] shrink-0">
                <Icon size={15} color="#D4AF37" />
              </div>
            )}
            <div>
              <div className="flex items-center gap-2">
                {title && (
                  <h3 className="text-sm font-semibold text-[#FAF9F5] tracking-tight font-heading">
                    {title}
                  </h3>
                )}
                {badge}
              </div>
              {description && (
                <p className="text-xs text-[#D1CBC0] mt-0.5 font-subheading font-light">
                  {description}
                </p>
              )}
            </div>
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}

      <div className={noPadding ? '' : 'p-5'}>{children}</div>
    </div>
  );
}
