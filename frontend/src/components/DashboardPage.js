import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { getUserInfo, getFileList, uploadFile } from '../api';
import FileCard from './FileCard';
import Header from './Header';
import StatCard from './StatCard';
import { HardDrive, File, UploadCloud, FileText, Database, Search } from 'react-feather';
import ErrorModal from './ErrorModal';
import Spinner from './Spinner';

const formatBytes = (bytes, decimals = 2) => {
  // Added a guard for null/undefined to prevent errors
  if (bytes === null || typeof bytes === 'undefined' || bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
};

const DashboardPage = ({ onLogout }) => {
  const [user, setUser] = useState(null);
  const [files, setFiles] = useState([]);
  const [errorModalMessage, setErrorModalMessage] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef(null);
  
  const [storageStats, setStorageStats] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Function to calculate stats. It will be called *after* files are fetched.
  const calculateAdminStats = (allFiles) => {
    if (!allFiles || allFiles.length === 0) {
      setStorageStats({ totalLogicalSize: 0, totalPhysicalSize: 0 });
      return;
    }

    const totalLogicalSize = allFiles.reduce((sum, file) => sum + file.Size, 0);

    const uniqueHashes = new Map();
    for (const file of allFiles) {
      if (!uniqueHashes.has(file.Hash)) {
        uniqueHashes.set(file.Hash, file.Size);
      }
    }
    const totalPhysicalSize = Array.from(uniqueHashes.values()).reduce((sum, size) => sum + size, 0);

    setStorageStats({ totalLogicalSize, totalPhysicalSize });
  };

  const fetchData = useCallback(async () => {
    try {
      // Fetch user and file data in parallel for efficiency
      const [userResponse, filesResponse] = await Promise.all([
        getUserInfo(),
        getFileList()
      ]);

      const [userSuccess, userData] = userResponse;
      const [filesSuccess, filesData] = filesResponse;

      // Only update state if BOTH API calls succeed
      if (userSuccess && filesSuccess) {
        const fetchedUser = userData;
        const fetchedFiles = filesData || [];

        setUser(fetchedUser);
        setFiles(fetchedFiles);

        // Now that we have the final data, perform calculations if admin
        if (fetchedUser.IsAdmin) {
          calculateAdminStats(fetchedFiles);
        }
      } else {
        // If either call fails, throw an error
        throw new Error(userData || filesData || 'Failed to fetch dashboard data.');
      }
    } catch (err) {
      setErrorModalMessage(err.message);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Memoized filter for search functionality
  const filteredFiles = useMemo(() => {
    if (!searchTerm) return files;
    return files.filter(file =>
      file.FileName.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (user?.IsAdmin && file.ID.toLowerCase().includes(searchTerm.toLowerCase()))
    );
  }, [files, searchTerm, user]);
  
  // Memoized calculation for the user's file count to fix case-sensitivity
  const userFileCount = useMemo(() => {
    if (!user || !files.length) return 0;
    // Fix: Compare IDs in a case-insensitive way
    return files.filter(f => f.ID.toLowerCase() === user.id.toLowerCase()).length;
  }, [user, files]);


  const handleUpload = async () => {
    if (!selectedFile) {
      setErrorModalMessage('Please select a file to upload first.');
      return;
    }
    setIsUploading(true);
    const [success, message] = await uploadFile(selectedFile);
    setIsUploading(false);

    if (success) {
      fetchData(); // Refresh file list
      setSelectedFile(null); // Reset selection
      if (fileInputRef.current) {
        fileInputRef.current.value = ''; // Reset the file input visually
      }
    } else {
      setErrorModalMessage(message || 'Upload failed.');
    }
  };

  if (!user) {
    return <div className="loading-screen">Loading Dashboard...</div>;
  }

  return (
    <div className="dashboard-wrapper">
      <Header user={user} onLogout={onLogout} />
      <main className="dashboard-main">
        <div className="stats-grid">
          {/* Your personal stats */}
          <StatCard icon={HardDrive} label="Your Storage Used" value={formatBytes(user.SizeUsed)} color="#007bff" />
          <StatCard icon={File} label="Your Total Files" value={userFileCount} color="#28a745" />

          {/* Admin-only stats - will now render correctly */}
          {user.IsAdmin && storageStats && (
            <>
              <StatCard icon={Database} label="Total Logical Storage" value={formatBytes(storageStats.totalLogicalSize)} color="#ffc107" />
              <StatCard icon={Database} label="Actual Physical Storage" value={formatBytes(storageStats.totalPhysicalSize)} color="#17a2b8" />
            </>
          )}
        </div>
        
        <div className="content-grid">
          <div className="file-list-container">
            <div className="file-list-header">
              <h3>{user.IsAdmin ? "All User Files" : "Your Files"}</h3>
              <div className="search-bar">
                <Search size={18} className="search-icon" />
                <input
                  type="search"
                  placeholder={user.IsAdmin ? "Search by filename or owner..." : "Search by filename..."}
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </div>
            </div>
            <div className="file-list">
              {filteredFiles.length > 0 ? (
                filteredFiles.map(file => (
                  <FileCard 
                    key={`${file.ID}-${file.FileId}`} 
                    file={file} 
                    onAction={fetchData} 
                    onError={setErrorModalMessage} 
                    isAdmin={user.IsAdmin}
                    currentUser={user}
                  />
                ))
              ) : (
                <div className="empty-state">
                  <FileText size={48} color="#adb5bd" />
                  <p>{searchTerm ? "No files match your search." : "You haven't uploaded any files yet."}</p>
                </div>
              )}
            </div>
          </div>
          <div className="upload-container">
            <h3>Upload New File</h3>
            <div
              className="upload-box"
              onClick={() => fileInputRef.current && fileInputRef.current.click()}
            >
              <input
                type="file"
                ref={fileInputRef}
                onChange={(e) => setSelectedFile(e.target.files[0])}
                style={{ display: 'none' }}
                disabled={isUploading}
              />
              <UploadCloud size={48} color="#007bff" />
              <p>
                {selectedFile ? selectedFile.name : 'Click file to upload'}
              </p>
            </div>
            <button
              className="upload-button"
              onClick={handleUpload}
              disabled={!selectedFile || isUploading}
            >
              {isUploading ? <Spinner size={20} /> : 'Upload File'}
            </button>
          </div>
        </div>
      </main>
      <ErrorModal message={errorModalMessage} onClose={() => setErrorModalMessage('')} />
    </div>
  );
};

export default DashboardPage;