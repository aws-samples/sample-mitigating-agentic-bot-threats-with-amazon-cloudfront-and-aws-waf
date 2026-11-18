import { useCallback, useState } from 'react';
import { FaceLivenessDetector } from '@aws-amplify/ui-react-liveness';
import { Alert, Button, Card, Flex, Heading, Loader, Text } from '@aws-amplify/ui-react';
import { createLivenessSession, verifyLivenessSession } from './api.js';

const MESSAGES = {
  challenge_required: 'This verification link has expired. Go back to the page you were visiting to start again.',
  waf_token_mismatch: 'Your browser session changed during the check. Go back to the page you were visiting and start again.',
  waf_challenge: 'Your browser needs to be checked again. Go back to the page you were visiting and start again.',
  liveness_session_expired: 'The check took too long. Please try again.',
  liveness_check_failed: "We couldn't confirm a live person. Use even lighting, face the camera, and try again.",
  too_many_verifications: 'Too many verification attempts. Please try again later.',
  request_blocked: 'Too many attempts from this browser or network. Wait 5 minutes, then go back to the page you were visiting and start again.',
  verification_unavailable: 'Verification is temporarily unavailable. Please try again in a few minutes.',
  rate_limited: 'Too many attempts from your network. Please wait a few minutes and try again.',
  camera: 'Camera access is required. Allow camera access in your browser settings and try again.',
  generic: 'Something went wrong. Please try again.',
};

function messageFor(result) {
  if (result.status === 429 && !result.data?.error) return MESSAGES.rate_limited; // AWS WAF rate limit
  return MESSAGES[result.data?.error] || MESSAGES.generic;
}

export default function App({ region, faceRetentionDays }) {
  // consent -> starting -> liveness -> (redirect) | failed | blocked
  const [phase, setPhase] = useState('consent');
  const [sessionId, setSessionId] = useState(null);
  const [message, setMessage] = useState('');

  const fail = useCallback((result) => {
    setSessionId(null);
    setMessage(messageFor(result));
    const terminal = ['challenge_required', 'waf_token_mismatch', 'waf_challenge', 'request_blocked', 'too_many_verifications'].includes(result.data?.error);
    setPhase(terminal ? 'blocked' : 'failed');
  }, []);

  const start = useCallback(async () => {
    setPhase('starting');
    setMessage('');
    const result = await createLivenessSession();
    if (result.ok && result.data.sessionId) {
      setSessionId(result.data.sessionId);
      setPhase('liveness');
    } else {
      fail(result);
    }
  }, [fail]);

  // Called by FaceLivenessDetector once the video has been analyzed. The
  // decision is made server-side; this page only learns pass or fail.
  const handleAnalysisComplete = useCallback(async () => {
    const result = await verifyLivenessSession();
    if (result.ok && result.data.verified) {
      window.location.replace(result.data.redirectUri || '/');
      return;
    }
    fail(result);
  }, [fail]);

  // Session IDs are single-use: any error requires a new session.
  const handleError = useCallback((livenessError) => {
    setSessionId(null);
    setMessage(livenessError?.state === 'CAMERA_ACCESS_ERROR' ? MESSAGES.camera : MESSAGES.generic);
    setPhase('failed');
  }, []);

  const handleCancel = useCallback(() => {
    setSessionId(null);
    setPhase('consent');
  }, []);

  if (phase === 'liveness' && sessionId) {
    return (
      <Card className="liveness-card" variation="elevated">
        <FaceLivenessDetector
          sessionId={sessionId}
          region={region}
          onAnalysisComplete={handleAnalysisComplete}
          onError={handleError}
          onUserCancel={handleCancel}
        />
      </Card>
    );
  }

  return (
    <Card className="liveness-card" variation="elevated">
      <Flex direction="column" gap="medium">
        <Heading level={1}>Confirm you're a person</Heading>
        <Text>
          We noticed activity on this session that looks automated. To continue, complete a short
          video check: follow the on-screen prompts to move your face while the screen shows a
          sequence of colors.
        </Text>
        <Text variation="secondary" fontSize="small">
          Your camera is used only for this check. The video is analyzed by Amazon Rekognition Face
          Liveness. A facial feature vector (not your photo) is kept for up to {faceRetentionDays} days
          after your last check, to limit how often the same face can be used to verify.
        </Text>

        {message && <Alert variation={phase === 'blocked' ? 'error' : 'warning'}>{message}</Alert>}

        {phase === 'starting' ? (
          <Loader size="large" ariaLabel="Starting the check" />
        ) : (
          phase !== 'blocked' && (
            <Button variation="primary" onClick={start}>
              {phase === 'failed' ? 'Try again' : 'Start the check'}
            </Button>
          )
        )}

        <Text variation="tertiary" fontSize="small">
          Can't use a camera, or prefer not to? Contact the site operator for another way to verify.
        </Text>
      </Flex>
    </Card>
  );
}
