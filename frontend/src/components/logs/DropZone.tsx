'use client';

import React, { useState, useRef } from 'react';
import { UploadCloud, FileCode2, CheckCircle2, AlertCircle, Sparkles } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import { uploadLogFile } from '@/lib/api';

interface DropZoneProps {
  onUploadSuccess: (sessionId: string, filename: string, lineCount: number) => void;
  className?: string;
}

export function DropZone({ onUploadSuccess, className }: DropZoneProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUploaded, setLastUploaded] = useState<{ name: string; size: number; lines: number } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      await processFile(e.target.files[0]);
    }
  };

  const processFile = async (file: File) => {
    setError(null);
    setIsUploading(true);

    try {
      const res = await uploadLogFile(file);
      setLastUploaded({
        name: res.filename,
        size: res.file_size,
        lines: res.total_lines,
      });
      onUploadSuccess(res.session_id, res.filename, res.total_lines);
    } catch (err: any) {
      setError(err?.message || 'Failed to upload log file');
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div
      style={{
        backgroundColor: '#0C1119',
        border: isDragging
          ? '1px dashed #3B82F6'
          : '1px dashed rgba(255, 255, 255, 0.12)',
        borderRadius: '12px',
        padding: '32px',
      }}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={`text-center font-sans transition-all ${className || ''}`}
    >
      <input
        ref={fileInputRef}
        type="file"
        accept=".log,.txt,.json,.csv"
        onChange={handleFileChange}
        className="hidden"
      />

      <div className="flex flex-col items-center justify-center max-w-md mx-auto space-y-3">
        <div
          className="w-12 h-12 rounded-xl flex items-center justify-center text-[#3B82F6]"
          style={{
            backgroundColor: 'rgba(59, 130, 246, 0.08)',
            border: '1px solid rgba(59, 130, 246, 0.2)',
          }}
        >
          <UploadCloud size={24} />
        </div>

        <div>
          <h3 className="text-sm font-semibold text-[#F5F7FA]">
            Upload Syslog or Security Telemetry
          </h3>
          <p className="text-xs text-[#A7B1C0] mt-1">
            Drag and drop your raw server logs, or browse files (.log, .txt, .csv)
          </p>
        </div>

        <div className="pt-2">
          <Button
            variant="primary"
            size="sm"
            isLoading={isUploading}
            onClick={() => fileInputRef.current?.click()}
          >
            Select Log File
          </Button>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-xs text-[#EF4444] bg-rose-500/10 border border-rose-500/25 px-3 py-1.5 rounded-lg mt-2">
            <AlertCircle size={14} />
            <span>{error}</span>
          </div>
        )}

        {lastUploaded && (
          <div className="flex items-center gap-2 text-xs text-[#22C55E] bg-emerald-500/10 border border-emerald-500/25 px-3 py-1.5 rounded-lg mt-2 font-mono">
            <CheckCircle2 size={14} />
            <span>Uploaded: {lastUploaded.name} ({lastUploaded.lines} lines)</span>
          </div>
        )}
      </div>
    </div>
  );
}
