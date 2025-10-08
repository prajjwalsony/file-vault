import React, { useState } from 'react';
import { login, register } from '../api';
import { User, Key } from 'react-feather';
import Spinner from './Spinner';
import ErrorModal from './ErrorModal'; // Import the modal

const AuthPage = ({ onLoginSuccess }) => {
  const [isLoginView, setIsLoginView] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  
  // State specifically for the error modal
  const [errorModalMessage, setErrorModalMessage] = useState('');
  // State for the success message shown on the page
  const [successMessage, setSuccessMessage] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !password) {
      setErrorModalMessage('Username and password are required.');
      return;
    }
    setIsLoading(true);
    setErrorModalMessage('');
    setSuccessMessage(''); // Clear previous success messages

    if (isLoginView) {
      const [success, errorMsg] = await login(username, password);
      setIsLoading(false);
      if (success) {
        onLoginSuccess();
      } else {
        setErrorModalMessage(errorMsg || 'An unknown error occurred.');
      }
    } else { // This is the registration logic
      const [success, errorMsg] = await register(username, password);
      setIsLoading(false);
      if (success) {
        setIsLoginView(true); // Switch back to the login view
        setSuccessMessage(errorMsg || 'Registration successful! You can now log in.');
        setPassword(''); // Clear the password field for security
      } else {
        // Set the message to show the modal on failure
        setErrorModalMessage(errorMsg || 'An unknown error occurred.');
      }
    }
  };

  return (
    <div className="auth-wrapper">
      <div className="auth-card">
        <div className="auth-header">
          <h2>SecureVault</h2>
          <p>{isLoginView ? 'Welcome back! Please log in.' : 'Create a new account.'}</p>
        </div>
        {/* Display success message here when it exists */}
        {successMessage && <div className="auth-message success">{successMessage}</div>}
        <form className="auth-form" onSubmit={handleSubmit}>
          <div className="input-group">
            <User className="input-icon" size={20} />
            <input type="text" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          </div>
          <div className="input-group">
            <Key className="input-icon" size={20} />
            <input type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <button type="submit" className="auth-button" disabled={isLoading}>
            {isLoading ? <Spinner size={20} /> : (isLoginView ? 'Login' : 'Register')}
          </button>
        </form>
        <div className="auth-footer">
          {isLoginView ? "Don't have an account?" : 'Already have an account?'}
          <button onClick={() => {
            setIsLoginView(!isLoginView);
            setErrorModalMessage('');
            setSuccessMessage(''); // Clear messages on view toggle
          }}>
            {isLoginView ? 'Register Now' : 'Login'}
          </button>
        </div>
      </div>
      {/* Render the modal which will appear when errorModalMessage is not empty */}
      <ErrorModal message={errorModalMessage} onClose={() => setErrorModalMessage('')} />
    </div>
  );
};

export default AuthPage;