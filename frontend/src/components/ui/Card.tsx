import React from 'react';
import { cn } from '@/lib/utils';

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  glass?: boolean;
  glow?: 'blue' | 'purple' | 'red' | 'emerald' | 'none';
  children: React.ReactNode;
}

export function Card({
  glass = true,
  glow = 'none',
  className,
  children,
  ...props
}: CardProps) {
  const glowStyles = {
    none: '',
    blue: 'border-blue-500/30 shadow-[0_0_24px_rgba(59,130,246,0.12)]',
    purple: 'border-purple-500/30 shadow-[0_0_24px_rgba(139,92,246,0.12)]',
    red: 'border-rose-500/30 shadow-[0_0_24px_rgba(239,68,68,0.12)]',
    emerald: 'border-emerald-500/30 shadow-[0_0_24px_rgba(34,197,94,0.12)]',
  }[glow];

  return (
    <div
      className={cn(
        'rounded-xl transition-all duration-150 font-sans',
        glowStyles,
        className
      )}
      style={{
        backgroundColor: '#0C1119',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.35)',
      }}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardHeader({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('px-5 py-4 border-b border-white/[0.06] flex items-center justify-between', className)}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardTitle({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      className={cn('text-sm font-semibold text-[#F5F7FA] tracking-tight', className)}
      {...props}
    >
      {children}
    </h3>
  );
}

export function CardDescription({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLParagraphElement>) {
  return (
    <p
      className={cn('text-xs text-[#A7B1C0] mt-0.5', className)}
      {...props}
    >
      {children}
    </p>
  );
}

export function CardContent({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn('p-5', className)} {...props}>
      {children}
    </div>
  );
}

export function CardFooter({
  className,
  children,
  ...props
}: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('px-5 py-3.5 border-t border-white/[0.06] flex items-center justify-between', className)}
      {...props}
    >
      {children}
    </div>
  );
}
