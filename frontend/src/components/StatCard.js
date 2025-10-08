

import React from 'react';

const StatCard = ({ icon, label, value, color }) => {
  const IconComponent = icon;
  
  return (
    <div className="stat-card">
      <div className="stat-icon" style={{ backgroundColor: color }}>
        <IconComponent size={24} color="white" />
      </div>
      <div className="stat-info">
        <span className="stat-label">{label}</span>
        <span className="stat-value">{value}</span>
      </div>
    </div>
  );
};

export default StatCard;