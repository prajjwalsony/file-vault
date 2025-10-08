import React from 'react';
import { LogOut } from 'react-feather';

const Header = ({ user, onLogout }) => {
  return (
    <div className="dashboard-header">
      <div className="logo">
        <h3>SecureVault</h3>
      </div>
      <div className="user-menu">
        <span>Welcome, <strong>{user.id}</strong>!</span>
        {user.IsAdmin && <span className="admin-badge">Admin</span>}
        <button onClick={onLogout} className="logout-button">
          <LogOut size={18} />
          <span>Logout</span>
        </button>
      </div>
    </div>
  );
};

// Make sure this line exists and is correct
export default Header;