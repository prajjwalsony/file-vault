import React from 'react';
import { XCircle, X } from 'react-feather';

const ErrorModal = ({ message, onClose }) => {
  if (!message) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>
          <X size={24} />
        </button>
        <div className="modal-icon">
          <XCircle size={48} color="#dc3545" />
        </div>
        <h4>An Error Occurred</h4>
        <p>{message}</p>
        <button className="modal-ok-button" onClick={onClose}>
          OK
        </button>
      </div>
    </div>
  );
};

export default ErrorModal;