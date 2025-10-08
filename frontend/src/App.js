import React, { useState, useEffect } from 'react';
import { getAuthState, clearAuth } from './api';
import AuthPage from './components/AuthPage';
import DashboardPage from './components/DashboardPage';
import './App.css';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check for an existing session when the app loads
    const authState = getAuthState();
    if (authState.loggedIn) {
      setIsLoggedIn(true);
    }
    setIsLoading(false);
  }, []);

  const handleLoginSuccess = () => {
    setIsLoggedIn(true);
  };

  const handleLogout = () => {
    clearAuth();
    setIsLoggedIn(false);
  };

  if (isLoading) {
    return <div>Loading Application...</div>;
  }

  return (
    <div className="App">
      {isLoggedIn ? (
        <DashboardPage onLogout={handleLogout} />
      ) : (
        <AuthPage onLoginSuccess={handleLoginSuccess} />
      )}
    </div>
  );
}



export default App;