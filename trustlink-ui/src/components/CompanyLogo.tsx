import { Building2 } from 'lucide-react';
import { customerLogoUrl } from '@/lib/api';
import { cn } from '@/lib/utils';

// 회사 로고(고객 등록부에 올린 것). 없으면 건물 아이콘. 중지된 회사는 흐리게.
export function CompanyLogo({ logo, size = 32, disabled, className }: { logo?: string; size?: number; disabled?: boolean; className?: string }) {
  return (
    <span className={cn('inline-flex shrink-0 items-center justify-center overflow-hidden rounded-md border border-slate-200 bg-white', disabled && 'opacity-40 grayscale', className)}
      style={{ width: size, height: size }}>
      {logo ? <img src={customerLogoUrl(logo)} alt="" className="max-h-full max-w-full object-contain p-0.5" loading="lazy" />
        : <Building2 size={Math.round(size * 0.55)} className="text-slate-400" />}
    </span>
  );
}
