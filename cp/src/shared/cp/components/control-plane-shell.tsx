import type { ReactNode } from 'react';
import type { ControlPlaneAccountDetail, FooterAction } from '@/features/accounts/contracts';
import { appInnerStyle, appPageStyle, bodyHeadingStyle, mutedTextStyle } from '../styles';
import { AccountContextBar } from './account-context-bar';
import { BreadcrumbHeader } from './breadcrumb-header';
import { FooterActionBar } from './footer-action-bar';
import { StepIndicator } from './step-indicator';

type ControlPlaneShellProps = {
  currentPath: string;
  pageTitle: string;
  pageDescription: string;
  children: ReactNode;
  footerActions: FooterAction[];
  account?: Pick<ControlPlaneAccountDetail, 'accountName' | 'accountKey' | 'step2Progress'>;
  step?: {
    stepNumber: 1 | 2 | 3;
    stepName: string;
  };
  showStepProgress?: boolean;
};

export function ControlPlaneShell({
  currentPath,
  pageTitle,
  pageDescription,
  children,
  footerActions,
  account,
  step,
  showStepProgress = false,
}: ControlPlaneShellProps) {
  return (
    <main style={appPageStyle}>
      <div style={appInnerStyle}>
        <BreadcrumbHeader currentPath={currentPath} />

        {step ? (
          <StepIndicator
            stepNumber={step.stepNumber}
            stepName={step.stepName}
            configuredCount={
              showStepProgress && account ? account.step2Progress.configuredCount : undefined
            }
            totalCount={showStepProgress && account ? account.step2Progress.totalCount : undefined}
          />
        ) : null}

        {account && step && step.stepNumber >= 2 ? <AccountContextBar account={account} /> : null}

        <section
          style={{
            padding: '8px 4px 0',
            display: 'grid',
            gap: '8px',
          }}
        >
          <h1 style={bodyHeadingStyle}>{pageTitle}</h1>
          <p style={mutedTextStyle}>{pageDescription}</p>
        </section>

        {children}

        <FooterActionBar actions={footerActions} />
      </div>
    </main>
  );
}
