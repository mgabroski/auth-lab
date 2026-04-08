import type { CSSProperties } from 'react';
import { panelStyle } from '../styles';

const indicatorStyle: CSSProperties = {
  ...panelStyle,
  padding: '16px 20px',
  display: 'grid',
  gap: '6px',
};

const titleStyle: CSSProperties = {
  margin: 0,
  fontSize: '16px',
  fontWeight: 700,
  color: '#0f172a',
};

const progressStyle: CSSProperties = {
  margin: 0,
  fontSize: '14px',
  lineHeight: 1.6,
  color: '#475569',
};

type StepIndicatorProps = {
  stepNumber: 1 | 2 | 3;
  stepName: string;
  reviewedCount?: number;
  totalCount?: number;
};

export function StepIndicator({
  stepNumber,
  stepName,
  reviewedCount,
  totalCount,
}: StepIndicatorProps) {
  const showProgress = stepNumber === 2 && reviewedCount !== undefined && totalCount !== undefined;

  return (
    <section aria-label="Current step" style={indicatorStyle}>
      <p style={titleStyle}>
        Step {stepNumber} of 3 — {stepName}
      </p>
      {showProgress ? (
        <p style={progressStyle}>
          Setup Progress: {reviewedCount} / {totalCount} sections reviewed
        </p>
      ) : null}
    </section>
  );
}
