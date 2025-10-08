import React, { useState } from 'react';
import { getFile, ChangeAccess, deleteFile } from '../api';
// import { Eye, Download, Lock, Unlock, Trash2, FileText, Link as LinkIcon, User } from 'react-feather';
import { Eye, Download, Lock, Unlock, Trash2, FileText, Link as LinkIcon, User, DownloadCloud } from 'react-feather';
import Spinner from './Spinner';

const BASE_URL = process.env.REACT_APP_BACKEND_URL || "http://localhost:3000";

const formatBytes = (bytes, decimals = 2) => {
  if (!bytes || bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

const FileCard = ({ file, onAction, onError, isAdmin, currentUser }) => {
  const [loadingAction, setLoadingAction] = useState(null);
  const [copyButtonText, setCopyButtonText] = useState('Copy Link');

  const handleAction = async (actionType, actionFn, ...args) => {
    setLoadingAction(actionType);
    const [success, message] = await actionFn(...args);
    setLoadingAction(null);

    if (success) {
      if (actionType !== 'view' && actionType !== 'download') {
         onAction();
      }
    } else {
      onError(message);
    }
  };

  const handleCopyLink = () => {
    // Construct the public URL for the file
    const publicLink = `${BASE_URL}/getFile?id=${file.ID}&fileId=${file.FileId}&action=view`;
    navigator.clipboard.writeText(publicLink).then(() => {
      setCopyButtonText('Copied!');
      setTimeout(() => setCopyButtonText('Copy Link'), 2000);
    });
  };

  const isPublic = file.Access === 'PUBLIC';
  
  // Determine if the current user can perform actions on this file.
  // This is true if:
  // 1. The user is NOT an admin (i.e., they are a regular user viewing their own files).
  // 2. The user IS an admin AND the file's owner ID matches the admin's own user ID.
  const canPerformActions = !isAdmin || (isAdmin && currentUser && currentUser.id.toLowerCase() === file.ID.toLowerCase());

  return (
    <div className="file-card">
      <div className="file-icon">
        <FileText size={32} color={isPublic ? '#28a745' : '#dc3545'} />
      </div>
      <div className="file-details">
        <h4 className="file-name">{file.FileName}</h4>
        <div className="file-meta">
          {isAdmin && (
            <span className="file-owner">
              <User size={12} /> {file.ID}
            </span>
          )}
          <span>ID: {file.FileId}</span>
          <span>Size: {formatBytes(file.Size)}</span>
          <span className={`file-access ${file.Access.toLowerCase()}`}>{file.Access}</span>
          {isPublic && typeof file.Downloads !== 'undefined' && (
            <span className="file-download-count" title="Total downloads">
              <DownloadCloud size={12} /> {file.Downloads}
            </span>
          )}
        </div>
      </div>
      <div className="file-actions">
        {/* Actions are only rendered if the user has permission */}
        {canPerformActions && (
          <>
            {/* View Button */}
            <button onClick={() => handleAction('view', getFile, file.FileId, 'view')} disabled={loadingAction} title="View">
              {loadingAction === 'view' ? <Spinner size={16} /> : <Eye size={16} />}
            </button>

            {/* Download Button */}
            <button onClick={() => handleAction('download', getFile, file.FileId, 'download')} disabled={loadingAction} title="Download">
              {loadingAction === 'download' ? <Spinner size={16} /> : <Download size={16} />}
            </button>

            {/* Change Access Button */}
            <button onClick={() => handleAction('access', ChangeAccess, file.FileId, isPublic ? 'PRIVATE' : 'PUBLIC')} disabled={loadingAction} title={isPublic ? 'Make Private' : 'Make Public'}>
              {loadingAction === 'access' ? <Spinner size={16} /> : (isPublic ? <Unlock size={16} /> : <Lock size={16} />)}
            </button>

            {/* Delete Button */}
            <button className="delete" onClick={() => {
              if (window.confirm('Are you sure you want to delete this file?')) {
                handleAction('delete', deleteFile, file.FileId);
              }
            }} disabled={loadingAction} title="Delete">
              {loadingAction === 'delete' ? <Spinner size={16} /> : <Trash2 size={16} />}
            </button>
          </>
        )}

        {/* Copy Link Button is available to both users and admins, but only if the file is public */}
        {isPublic && (
          <button onClick={handleCopyLink} className="copy-link-button" title="Copy public link">
            {copyButtonText === 'Copied!' ? 'Copied!' : <LinkIcon size={16} />}
          </button>
        )}
      </div>
    </div>
  );
};

export default FileCard;