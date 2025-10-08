import React from 'react';

const Spinner = ({ size = 16 }) => {
  return (
    // The className is used by App.css to apply the spinning animation
    <div className="spinner" style={{ width: `${size}px`, height: `${size}px` }}></div>
  );
};

export default Spinner;