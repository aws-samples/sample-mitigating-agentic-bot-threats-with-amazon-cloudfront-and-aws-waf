import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { Amplify } from 'aws-amplify';
import { ThemeProvider } from '@aws-amplify/ui-react';
import '@aws-amplify/ui-react/styles.css';
import './styles.css';
import App from './App.jsx';

const root = document.getElementById('root');

async function bootstrap() {
  // config.json is written by CDK at deploy time (identity pool ID, Region).
  const response = await fetch(`${import.meta.env.BASE_URL}config.json`, { cache: 'no-store' });
  if (!response.ok) throw new Error('config unavailable');
  const config = await response.json();

  // The identity pool only vends guest credentials, which FaceLivenessDetector
  // uses to sign the StartFaceLivenessSession video stream.
  Amplify.configure({
    Auth: { Cognito: { identityPoolId: config.identityPoolId, allowGuestAccess: true } },
  });

  createRoot(root).render(
    <StrictMode>
      <ThemeProvider>
        <App region={config.region} faceRetentionDays={config.faceRetentionDays} />
      </ThemeProvider>
    </StrictMode>,
  );
}

bootstrap().catch(() => {
  root.textContent = 'Verification is temporarily unavailable. Please try again later.';
});
