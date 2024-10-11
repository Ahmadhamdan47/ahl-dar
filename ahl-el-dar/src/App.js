// src/App.js
import React, { useState } from 'react';
import SignIn from './components/SignIn';
import SignUp from './components/SignUp';
import HouseList from './components/HouseList';
import AddHouse from './components/AddHouse';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(false); // Check if user is logged in
  const [showSignUp, setShowSignUp] = useState(false); // Toggle between sign in and sign up
  const [showAddHouse, setShowAddHouse] = useState(false); // Toggle between house listings and add house form

  const handleToggleSignUp = () => setShowSignUp(!showSignUp);

  return (
    <div className="min-h-screen bg-gray-100">
      <header className="bg-blue-600 p-4 text-white text-center">
        <h1 className="text-2xl font-semibold">Ahl El Dar</h1>
      </header>

      <main className="py-8">
        {!isLoggedIn ? (
          <div className="container mx-auto px-4 py-8">
            {showSignUp ? (
              <>
                <SignUp setIsLoggedIn={setIsLoggedIn} />
                <button
                  className="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                  onClick={handleToggleSignUp}
                >
                  Already have an account? Sign In
                </button>
              </>
            ) : (
              <>
                <SignIn setIsLoggedIn={setIsLoggedIn} />
                <button
                  className="mt-4 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                  onClick={handleToggleSignUp}
                >
                  Don't have an account? Sign Up
                </button>
              </>
            )}
          </div>
        ) : (
          <div className="container mx-auto px-4 py-8">
            <button
              className="mb-6 px-4 py-2 bg-white text-blue-600 rounded hover:bg-blue-200"
              onClick={() => setShowAddHouse(!showAddHouse)}
            >
              {showAddHouse ? "View House Listings" : "Add New House"}
            </button>

            {showAddHouse ? <AddHouse /> : <HouseList />}
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
