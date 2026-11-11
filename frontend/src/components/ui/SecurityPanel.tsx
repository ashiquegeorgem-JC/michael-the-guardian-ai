import React from 'react';
import { cn } from '@/lib/utils';

interface SecurityPanelProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  icon?: React.ComponentType<{ className?: string; size?: number }>;
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  actions?: React.ReactNode;
  badge?: React.ReactNode;
  children: React.ReactNode;
}

export function SecurityPanel({
  icon: Icon,
  title,
  subtitle,
  actions,
  badge,
  className,
  children,
  ...props
}: SecurityPanelProps) {
  return (
    <div
      className={cn(
        'rounded-xl border border-white/[0.08] bg-[#0C1119] p-5 shadow-lg shadow-black/40 transition-all duration-150 font-sans',
        className
      )}
      style={{
        backgroundColor: '#0C1119',
        border: '1px solid rgba(255, 255, 255, 0.08)',
      }}
      {...props}
    >
      {(title || actions || Icon) && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.06] pb-3 mb-4">
          <div className="flex items-center gap-2.5">
            {Icon && (
              <div className="w-7 h-7 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-[#3B82F6] shrink-0">
                <Icon size={15} />
              </div>
            )}
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold tracking-normal text-[#F5F7FA]">
                  {title}
                </h3>
                {badge}
              </div>
              {subtitle && (
                <p className="text-xs text-[#A7B1C0] mt-0.5">
                  {subtitle}
                </p>
              )}
            </div>
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      <div>{children}</div>
    </div>
  );
}
