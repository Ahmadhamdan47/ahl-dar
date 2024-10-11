// src/components/SignUp.js
import React, { useState } from 'react';
import axios from 'axios';

const SignUp = ({ setIsLoggedIn }) => {
  const [formData, setFormData] = useState({
    phoneNumber: '',
    password: '',
    name: '',
    email: '',
    address: '',
    city: '',
    region: '',
    district: '',
    age: '',
    sex: 'male', // Default value
  });

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSignUp = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:3000/signup', formData);
      alert('Sign up successful');
    } catch (error) {
      console.error('Sign-up error:', error);
      alert('Sign-up failed');
    }
  };

  return (
    <div className="w-full max-w-md p-6 bg-white rounded-md shadow-md">
      <h2 className="text-2xl font-semibold text-center">Sign Up</h2>
      <form onSubmit={handleSignUp} className="mt-4">
        <div className="mb-4">
          <label className="block text-sm">Name</label>
          <input
            type="text"
            name="name"
            value={formData.name}
            onChange={handleChange}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter your name"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Phone Number</label>
          <input
            type="text"
            name="phoneNumber"
            value={formData.phoneNumber}
            onChange={handleChange}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter phone number"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Email</label>
          <input
            type="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter your email"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Password</label>
          <input
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter password"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Address</label>
          <input
            type="text"
            name="address"
            value={formData.address}
            onChange={handleChange}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter your address"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">City</label>
          <input
            type="text"
            name="city"
            value={formData.city}
            onChange={handleChange}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter your city"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Region</label>
          <input
            type="text"
            name="region"
            value={formData.region}
            onChange={handleChange}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter your region"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">District</label>
          <input
            type="text"
            name="district"
            value={formData.district}
            onChange={handleChange}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter your district"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Age</label>
          <input
            type="number"
            name="age"
            value={formData.age}
            onChange={handleChange}
            className="w-full px-3 py-2 border rounded-md"
            placeholder="Enter your age"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Sex</label>
          <select
            name="sex"
            value={formData.sex}
            onChange={handleChange}
            className="w-full px-3 py-2 border rounded-md"
          >
            <option value="male">Male</option>
            <option value="female">Female</option>
            <option value="other">Other</option>
          </select>
        </div>
        <button
          type="submit"
          className="w-full px-4 py-2 text-white bg-blue-600 rounded-md hover:bg-blue-700"
        >
          Sign Up
        </button>
      </form>
    </div>
  );
};

export default SignUp;
