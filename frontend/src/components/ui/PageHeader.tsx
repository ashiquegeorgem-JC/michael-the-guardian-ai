import React from 'react';

interface PageHeaderProps {
  title: string;
  description: React.ReactNode;
  tag?: string;
  actions?: React.ReactNode;
  children?: React.ReactNode;
}

export function PageHeader({
  title,
  description,
  tag,
  actions,
  children,
}: PageHeaderProps) {
  return (
    <div className="flex flex-col gap-3 pb-3 mb-6 border-b border-white/[0.06] font-sans">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          {tag && (
            <div className="flex items-center gap-2 mb-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#34D399]" />
              <span className="text-[10px] font-semibold text-[#94A3B8] uppercase tracking-wider font-subheading">
                {tag}
              </span>
            </div>
          )}
          <h1 className="text-xl md:text-2xl font-semibold tracking-tight text-white font-heading">
            {title}
          </h1>
          <div className="text-xs text-[#94A3B8] font-subheading mt-1 max-w-3xl leading-relaxed whitespace-pre-line">
            {description}
          </div>
        </div>

        {actions && (
          <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
            {actions}
          </div>
        )}
      </div>

      {children && <div className="pt-2">{children}</div>}
    </div>
  );
}
