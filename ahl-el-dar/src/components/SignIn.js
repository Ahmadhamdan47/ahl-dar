// src/components/SignIn.js
import React, { useState } from 'react';
import axios from 'axios';

const SignIn = ({ setIsLoggedIn }) => {
  const [phoneNumber, setPhoneNumber] = useState('');
  const [password, setPassword] = useState('');

  const handleSignIn = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:3000/login', {
        phoneNumber,
        password,
      });

      const token = response.data.token;
      localStorage.setItem('token', token); // Save the token for future requests
      setIsLoggedIn(true);
      alert('Sign in successful');
    } catch (error) {
      console.error('Sign-in error:', error);
      alert('Sign-in failed');
    }
  };

  return (
    <div className="w-full max-w-md p-6 bg-white rounded-md shadow-md mt-6">
      <h2 className="text-2xl font-semibold text-center">Sign In</h2>
      <form onSubmit={handleSignIn} className="mt-4">
        <div className="mb-4">
          <label className="block text-sm">Phone Number</label>
          <input
            type="text"
            value={phoneNumber}
            onChange={(e) => setPhoneNumber(e.target.value)}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter phone number"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter password"
          />
        </div>
        <button
          type="submit"
          className="w-full px-4 py-2 text-white bg-green-600 rounded-md hover:bg-green-700"
        >
          Sign In
        </button>
      </form>
    </div>
  );
};

export default SignIn;
