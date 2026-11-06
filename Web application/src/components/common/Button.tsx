import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'outline' | 'ghost';
  size?: 'xs' | 'sm' | 'md' | 'lg';
  icon?: React.ReactNode;
  isLoading?: boolean;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'secondary',
  size = 'md',
  icon,
  isLoading = false,
  className = '',
  disabled,
  ...props
}) => {
  const sizeClasses = {
    xs: 'px-2 py-1 text-xs',
    sm: 'px-3 py-1.5 text-xs',
    md: 'px-4 py-2 text-sm',
    lg: 'px-5 py-2.5 text-base',
  };

  const variantClasses = {
    primary:
      'bg-blue-600 hover:bg-blue-700 text-white font-semibold shadow-xs focus:ring-2 focus:ring-blue-400 focus:outline-none dark:bg-cyan-500 dark:hover:bg-cyan-400 dark:text-slate-950',
    secondary:
      'bg-slate-100 hover:bg-slate-200 text-slate-800 border border-slate-300 focus:ring-2 focus:ring-slate-400 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-slate-100 dark:border-slate-700',
    danger:
      'bg-rose-600 hover:bg-rose-700 text-white font-semibold focus:ring-2 focus:ring-rose-500 shadow-xs dark:bg-rose-700 dark:hover:bg-rose-600',
    outline:
      'bg-transparent hover:bg-slate-100 text-slate-700 border border-slate-300 focus:ring-2 focus:ring-slate-400 dark:hover:bg-slate-800/60 dark:text-slate-300 dark:border-slate-700',
    ghost:
      'bg-transparent hover:bg-slate-100 text-slate-700 focus:ring-2 focus:ring-slate-400 dark:hover:bg-slate-800 dark:text-slate-300',
  };

  return (
    <button
      className={`inline-flex items-center justify-center gap-2 rounded font-medium transition-all duration-150 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${sizeClasses[size]} ${variantClasses[variant]} ${className}`}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <span className="w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
      ) : (
        icon
      )}
      {children}
    </button>
  );
};
