import MedusaDashboard from './MedusaDashboard';

export default function Page() {
  // This runs on the server at request time, so process.env is available
  const apiUrl = process.env.MEDUSA_API_URL || process.env.NEXT_PUBLIC_MEDUSA_API_URL || 'http://localhost:5000';
  
  return <MedusaDashboard apiUrl={apiUrl} />;
}
