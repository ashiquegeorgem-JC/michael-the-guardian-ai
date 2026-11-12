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
    blue: 'border-sky-500/30 shadow-[0_0_24px_rgba(56,189,248,0.15)]',
    purple: 'border-purple-500/30 shadow-[0_0_24px_rgba(167,139,250,0.15)]',
    red: 'border-rose-500/30 shadow-[0_0_24px_rgba(248,113,113,0.15)]',
    emerald: 'border-emerald-500/30 shadow-[0_0_24px_rgba(52,211,153,0.15)]',
  }[glow];

  return (
    <div
      className={cn(
        'rounded-2xl transition-all duration-150 font-sans overflow-hidden hover:border-white/20',
        glowStyles,
        className
      )}
      style={{
        backgroundColor: '#11161E',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.35)',
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
      className={cn(
        'px-6 py-4 border-b border-white/[0.07] bg-[#0D1117] flex items-center justify-between',
        className
      )}
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
      className={cn('text-sm font-heading font-semibold text-white tracking-wide', className)}
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
      className={cn('text-xs text-[#94A3B8] font-subheading mt-0.5', className)}
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
    <div className={cn('p-6', className)} {...props}>
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
      className={cn(
        'px-6 py-3.5 border-t border-white/[0.07] bg-[#090D13] flex items-center justify-between text-xs text-[#94A3B8]',
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}
