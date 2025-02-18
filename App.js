import VulnerabilityChecker from './components/VulnerabilityChecker';

function App() {
  return (
    <div className="min-h-screen bg-gray-50 py-12">
      <header className="text-center mb-12">
        <h1 className="text-4xl font-bold text-gray-800">रक्षक</h1><h4>(The Website Vulnerability Scanner)</h4>
        <p className="text-gray-600 mt-2">Introducing "Rakshak" - The Website Vulnerability Scanner!<h4>
         Ensure your website's security by detecting common vulnerabilities before they become threats.</h4>
         Enter your URL and scan effortlessly to protect your online presence. Stay secure with Rakshak!</p>
      </header>
      <VulnerabilityChecker />
    </div>
  );
}

export default App;
