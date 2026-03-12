/**
 * frontend/src/shared/auth/components/auth-form-ui.tsx
 *
 * WHY:
 * - Shared low-level auth form primitives for the Phase 3 public entry screens.
 * - Keeps forms visually consistent without introducing a large UI framework.
 */

import Link from 'next/link';
import type { CSSProperties, InputHTMLAttributes, ReactNode, TextareaHTMLAttributes } from 'react';

const stackBaseStyle: CSSProperties = {
  display: 'grid',
  gap: '16px',
};

const fieldStyle: CSSProperties = {
  display: 'grid',
  gap: '8px',
};

const labelStyle: CSSProperties = {
  fontSize: '14px',
  fontWeight: 600,
  color: '#0f172a',
};

const inputStyle: CSSProperties = {
  width: '100%',
  minHeight: '46px',
  borderRadius: '12px',
  border: '1px solid rgba(148, 163, 184, 0.45)',
  backgroundColor: '#ffffff',
  color: '#0f172a',
  padding: '12px 14px',
  fontSize: '14px',
  lineHeight: 1.4,
  outline: 'none',
  boxSizing: 'border-box',
};

const hintStyle: CSSProperties = {
  fontSize: '13px',
  lineHeight: 1.5,
  color: '#64748b',
};

const buttonStyle: CSSProperties = {
  width: '100%',
  minHeight: '46px',
  borderRadius: '12px',
  border: 'none',
  backgroundColor: '#0f172a',
  color: '#ffffff',
  padding: '12px 16px',
  fontSize: '14px',
  fontWeight: 700,
  cursor: 'pointer',
};

const secondaryButtonStyle: CSSProperties = {
  ...buttonStyle,
  border: '1px solid rgba(148, 163, 184, 0.35)',
  backgroundColor: '#ffffff',
  color: '#0f172a',
};

const dividerWrapStyle: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: '1fr auto 1fr',
  gap: '12px',
  alignItems: 'center',
  color: '#64748b',
  fontSize: '13px',
};

const dividerLineStyle: CSSProperties = {
  height: '1px',
  backgroundColor: 'rgba(148, 163, 184, 0.28)',
};

const rowStyle: CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  gap: '12px',
  flexWrap: 'wrap',
  fontSize: '14px',
  lineHeight: 1.6,
  color: '#475569',
};

const linkGroupStyle: CSSProperties = {
  display: 'flex',
  flexWrap: 'wrap',
  gap: '12px',
  fontSize: '14px',
  lineHeight: 1.6,
};

const noteStyle: CSSProperties = {
  borderRadius: '14px',
  border: '1px solid rgba(148, 163, 184, 0.22)',
  backgroundColor: 'rgba(248, 250, 252, 0.92)',
  padding: '14px 16px',
  fontSize: '14px',
  lineHeight: 1.6,
  color: '#334155',
};

type FieldProps = {
  label: string;
  htmlFor: string;
  hint?: ReactNode;
  children: ReactNode;
};

export function FormStack({ children }: { children: ReactNode }) {
  return <div style={stackBaseStyle}>{children}</div>;
}

export function FormField({ label, htmlFor, hint, children }: FieldProps) {
  return (
    <label htmlFor={htmlFor} style={fieldStyle}>
      <span style={labelStyle}>{label}</span>
      {children}
      {hint ? <span style={hintStyle}>{hint}</span> : null}
    </label>
  );
}

export function TextInput(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} style={{ ...inputStyle, ...props.style }} />;
}

export function TextArea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      style={{ ...inputStyle, minHeight: '100px', resize: 'vertical', ...props.style }}
    />
  );
}

export function SubmitButton({ children, disabled }: { children: ReactNode; disabled?: boolean }) {
  return (
    <button type="submit" style={buttonStyle} disabled={disabled}>
      {children}
    </button>
  );
}

export function SecondaryButton({
  children,
  disabled,
  type = 'button',
  onClick,
}: {
  children: ReactNode;
  disabled?: boolean;
  type?: 'button' | 'submit' | 'reset';
  onClick?: () => void;
}) {
  return (
    <button type={type} style={secondaryButtonStyle} disabled={disabled} onClick={onClick}>
      {children}
    </button>
  );
}

export function FormDivider({ label = 'or' }: { label?: string }) {
  return (
    <div aria-hidden="true" style={dividerWrapStyle}>
      <div style={dividerLineStyle} />
      <span>{label}</span>
      <div style={dividerLineStyle} />
    </div>
  );
}

export function FormRow({ left, right }: { left?: ReactNode; right?: ReactNode }) {
  return (
    <div style={rowStyle}>
      <div>{left}</div>
      <div>{right}</div>
    </div>
  );
}

export function AuthLinkGroup({ children }: { children: ReactNode }) {
  return <div style={linkGroupStyle}>{children}</div>;
}

export function AuthInlineLink({ href, children }: { href: string; children: ReactNode }) {
  return <Link href={href}>{children}</Link>;
}

export function AuthNote({ children }: { children: ReactNode }) {
  return <div style={noteStyle}>{children}</div>;
}
