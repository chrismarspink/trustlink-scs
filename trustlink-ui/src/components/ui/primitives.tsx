import * as React from 'react';
import { cn } from '@/lib/utils';

// shadcn/ui 스타일 프리미티브 (소유 컴포넌트, Tailwind 기반)
export function Button({
  className,
  variant = 'default',
  size = 'default',
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'default' | 'outline' | 'ghost' | 'accent' | 'destructive';
  size?: 'default' | 'sm' | 'icon';
}) {
  const variants = {
    default: 'bg-primary text-primary-foreground shadow-sm hover:bg-primary/90',
    outline: 'border border-input bg-background shadow-sm hover:bg-secondary',
    ghost: 'hover:bg-secondary',
    accent: 'bg-primary text-primary-foreground shadow-sm hover:bg-primary/90',
    destructive: 'bg-destructive text-destructive-foreground shadow-sm hover:bg-destructive/90'
  };
  const sizes = { default: 'h-9 px-4 text-sm', sm: 'h-8 px-3 text-xs', icon: 'h-8 w-8' };
  return (
    <button
      className={cn(
        'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50',
        variants[variant],
        sizes[size],
        className
      )}
      {...props}
    />
  );
}

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('rounded-lg border bg-card text-card-foreground shadow-sm', className)} {...props} />;
}
export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('p-5 pb-2', className)} {...props} />;
}
export function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('p-5 pt-2', className)} {...props} />;
}

export function Badge({
  className,
  variant = 'default',
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & { variant?: 'default' | 'success' | 'warn' | 'danger' | 'muted' | 'outline' }) {
  const variants = {
    default: 'border-transparent bg-primary text-primary-foreground',
    success: 'border-transparent bg-emerald-50 text-emerald-700',
    warn: 'border-transparent bg-amber-50 text-amber-700',
    danger: 'border-transparent bg-red-50 text-red-700',
    muted: 'border-transparent bg-secondary text-secondary-foreground',
    outline: 'text-foreground'
  };
  return (
    <span
      className={cn('inline-flex items-center rounded-md border px-1.5 py-0.5 text-xs font-medium', variants[variant], className)}
      {...props}
    />
  );
}

// 상태 표시 — 배지 대신 점 + 글자
export function StatusDot({ tone, children }: { tone: 'ok' | 'off' | 'warn' | 'crit'; children: React.ReactNode }) {
  const dot = { ok: 'bg-emerald-500', off: 'bg-zinc-300', warn: 'bg-amber-500', crit: 'bg-red-500' }[tone];
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className={cn('h-1.5 w-1.5 rounded-full', dot)} />
      {children}
    </span>
  );
}

export function Input({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        'flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring',
        className
      )}
      {...props}
    />
  );
}

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn('text-sm font-medium leading-none', className)} {...props} />;
}
