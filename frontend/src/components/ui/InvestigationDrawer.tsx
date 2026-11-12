'use client';

import React, { useEffect } from 'react';
import { X } from 'lucide-react';

interface InvestigationDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  width?: string | number;
}

export function InvestigationDrawer({
  isOpen,
  onClose,
  title,
  subtitle,
  children,
  width = 480,
}: InvestigationDrawerProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden font-sans">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-xs transition-opacity"
        onClick={onClose}
      />

      {/* Drawer Panel */}
      <div
        className="fixed inset-y-0 right-0 flex max-w-full pl-10"
        style={{ width: typeof width === 'number' ? `${width}px` : width }}
      >
        <div
          className="w-full flex flex-col bg-[#11161E] border-l border-white/[0.08] shadow-2xl"
          style={{ backgroundColor: '#11161E' }}
        >
          {/* Drawer Header */}
          <div className="flex items-center justify-between px-6 py-5 border-b border-white/[0.08] shrink-0 bg-[#0D1117]">
            <div>
              <h3 className="text-base font-semibold text-[#F5F7FA] tracking-tight">
                {title}
              </h3>
              {subtitle && (
                <p className="text-xs text-[#A7B1C0] mt-0.5 font-mono">
                  {subtitle}
                </p>
              )}
            </div>
            <button
              onClick={onClose}
              className="w-8 h-8 rounded-lg flex items-center justify-center text-[#A7B1C0] hover:text-[#F5F7FA] hover:bg-white/[0.06] transition-colors"
            >
              <X size={16} />
            </button>
          </div>

          {/* Drawer Content */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}

