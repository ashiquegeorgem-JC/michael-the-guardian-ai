import React from 'react';
import { cn } from '@/lib/utils';
import { Loader2 } from 'lucide-react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'outline' | 'danger' | 'success' | 'ghost' | 'glass';
  size?: 'sm' | 'md' | 'lg' | 'icon';
  isLoading?: boolean;
  leftIcon?: React.ReactNode;
  rightIcon?: React.ReactNode;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = 'primary',
      size = 'md',
      isLoading = false,
      leftIcon,
      rightIcon,
      disabled,
      children,
      style,
      ...props
    },
    ref
  ) => {
    const baseStyles =
      'relative inline-flex items-center justify-center font-sans font-medium rounded-lg transition-all duration-150 select-none focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed active:scale-[0.98] cursor-pointer';

    const variants = {
      primary:
        'bg-[#3B82F6] hover:bg-[#2563EB] text-white shadow-sm border border-blue-400/20',
      secondary:
        'bg-[#0C1119] hover:bg-[#111823] text-[#F5F7FA] border border-white/[0.08]',
      outline:
        'bg-transparent hover:bg-white/[0.04] text-[#F5F7FA] border border-white/[0.1]',
      danger:
        'bg-[#EF4444] hover:bg-[#DC2626] text-white shadow-sm border border-rose-400/20',
      success:
        'bg-[#22C55E] hover:bg-[#16A34A] text-white shadow-sm border border-emerald-400/20',
      ghost:
        'bg-transparent hover:bg-white/[0.04] text-[#A7B1C0] hover:text-[#F5F7FA]',
      glass:
        'bg-[#0C1119]/80 hover:bg-[#111823] text-[#F5F7FA] border border-white/[0.07] backdrop-blur-xs',
    };

    const sizes = {
      sm: 'text-xs px-3 py-1.5 gap-1.5',
      md: 'text-xs px-3.5 py-2 gap-2',
      lg: 'text-sm px-4 py-2.5 gap-2.5',
      icon: 'h-8 w-8 p-0 flex items-center justify-center',
    };

    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={cn(baseStyles, variants[variant], sizes[size], className)}
        style={style}
        {...props}
      >
        {isLoading ? (
          <>
            <Loader2 className="animate-spin mr-1.5" size={14} />
            <span>Loading...</span>
          </>
        ) : (
          <>
            {leftIcon && <span className="shrink-0">{leftIcon}</span>}
            {children}
            {rightIcon && <span className="shrink-0">{rightIcon}</span>}
          </>
        )}
      </button>
    );
  }
);

Button.displayName = 'Button';
