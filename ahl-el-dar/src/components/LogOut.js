// src/components/LogOut.js
import React from 'react';

const LogOut = ({ setIsLoggedIn }) => {
  const handleLogOut = () => {
    localStorage.removeItem('token'); // Remove the JWT token
    setIsLoggedIn(false);
    alert('Logged out successfully');
  };

  return (
    <div className="w-full max-w-md p-6 bg-white rounded-md shadow-md text-center">
      <h2 className="text-2xl font-semibold">Welcome to Ahl El Dar</h2>
      <button
        onClick={handleLogOut}
        className="mt-6 px-4 py-2 text-white bg-red-600 rounded-md hover:bg-red-700"
      >
        Log Out
      </button>
    </div>
  );
};

export default LogOut;
