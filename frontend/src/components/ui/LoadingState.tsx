import React from 'react';

interface LoadingStateProps {
  rows?: number;
  type?: 'table' | 'cards' | 'page' | 'metric';
}

export function LoadingState({ rows = 5, type = 'table' }: LoadingStateProps) {
  if (type === 'metric') {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 animate-pulse">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-28 rounded-xl bg-[#0C1119] border border-white/[0.06] p-4 flex flex-col justify-between"
          >
            <div className="h-3 w-24 bg-white/[0.06] rounded" />
            <div className="h-7 w-32 bg-white/[0.1] rounded" />
            <div className="h-2.5 w-16 bg-white/[0.04] rounded" />
          </div>
        ))}
      </div>
    );
  }

  if (type === 'cards') {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 animate-pulse">
        {Array.from({ length: 6 }).map((_, i) => (
          <div
            key={i}
            className="h-44 rounded-xl bg-[#0C1119] border border-white/[0.06] p-5 space-y-3"
          >
            <div className="h-4 w-3/4 bg-white/[0.08] rounded" />
            <div className="h-3 w-1/2 bg-white/[0.05] rounded" />
            <div className="h-16 w-full bg-white/[0.03] rounded mt-4" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="rounded-xl bg-[#0C1119] border border-white/[0.06] p-5 space-y-3.5 animate-pulse">
      <div className="flex items-center justify-between pb-3 border-b border-white/[0.06]">
        <div className="h-4 w-36 bg-white/[0.08] rounded" />
        <div className="h-3 w-20 bg-white/[0.05] rounded" />
      </div>
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="flex items-center justify-between py-2 border-b border-white/[0.03] gap-4"
        >
          <div className="h-3.5 w-16 bg-white/[0.06] rounded" />
          <div className="h-3.5 w-1/3 bg-white/[0.06] rounded" />
          <div className="h-3.5 w-24 bg-white/[0.04] rounded hidden sm:block" />
          <div className="h-3.5 w-16 bg-white/[0.05] rounded" />
        </div>
      ))}
    </div>
  );
}

