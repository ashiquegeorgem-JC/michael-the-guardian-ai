import React from 'react';

interface PageHeaderProps {
  title: string;
  description: string;
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
    <div className="flex flex-col gap-4 pb-2 mb-6 border-b border-[rgba(212,175,55,0.12)] font-sans">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          {tag && (
            <div className="flex items-center gap-2 mb-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-[#D4AF37] shadow-[0_0_8px_rgba(212,175,55,0.8)]" />
              <span className="text-xs font-semibold text-[#D4AF37] uppercase tracking-wider font-subheading">
                {tag}
              </span>
            </div>
          )}
          <h1 className="text-2xl md:text-3xl font-bold tracking-tight text-[#FAF9F5] font-heading">
            {title}
          </h1>
          <p className="text-sm text-[#D1CBC0] font-subheading font-light mt-1.5 max-w-2xl leading-relaxed">
            {description}
          </p>
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
