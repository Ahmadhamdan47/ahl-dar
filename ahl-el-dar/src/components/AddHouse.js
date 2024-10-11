// src/components/AddHouse.js
import React, { useState } from 'react';
import axios from 'axios';

const AddHouse = () => {
  const [formData, setFormData] = useState({
    address: '',
    region: '',
    district: '',
    town: '',
    size: '',
    capacity: '',
    photos: [],
    furnished: false,
    for_rent: false,
    rent_amount: '',
    phone_number: '',
  });

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleCheckboxChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.checked,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem('token'); // Ensure the user is logged in
      const response = await axios.post('http://localhost:3000/houses', formData, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      alert('House added successfully!');
    } catch (error) {
      console.error('Error adding house:', error);
      alert('Failed to add house');
    }
  };

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-2xl font-semibold mb-6">Add a New House</h1>
      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <label className="block text-sm">Address</label>
          <input
            type="text"
            name="address"
            value={formData.address}
            onChange={handleChange}
            className="w-full p-2 border rounded"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Region</label>
          <input
            type="text"
            name="region"
            value={formData.region}
            onChange={handleChange}
            className="w-full p-2 border rounded"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">District</label>
          <input
            type="text"
            name="district"
            value={formData.district}
            onChange={handleChange}
            className="w-full p-2 border rounded"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Town</label>
          <input
            type="text"
            name="town"
            value={formData.town}
            onChange={handleChange}
            className="w-full p-2 border rounded"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Size (sqm)</label>
          <input
            type="number"
            name="size"
            value={formData.size}
            onChange={handleChange}
            className="w-full p-2 border rounded"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Capacity</label>
          <input
            type="number"
            name="capacity"
            value={formData.capacity}
            onChange={handleChange}
            className="w-full p-2 border rounded"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Phone Number</label>
          <input
            type="text"
            name="phone_number"
            value={formData.phone_number}
            onChange={handleChange}
            className="w-full p-2 border rounded"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Photos (Comma-separated URLs)</label>
          <input
            type="text"
            name="photos"
            value={formData.photos.join(',')}
            onChange={(e) =>
              setFormData({
                ...formData,
                photos: e.target.value.split(',').map((url) => url.trim()),
              })
            }
            className="w-full p-2 border rounded"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">Furnished</label>
          <input
            type="checkbox"
            name="furnished"
            checked={formData.furnished}
            onChange={handleCheckboxChange}
            className="ml-2"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm">For Rent</label>
          <input
            type="checkbox"
            name="for_rent"
            checked={formData.for_rent}
            onChange={handleCheckboxChange}
            className="ml-2"
          />
        </div>
        {formData.for_rent && (
          <div className="mb-4">
            <label className="block text-sm">Rent Amount</label>
            <input
              type="number"
              name="rent_amount"
              value={formData.rent_amount}
              onChange={handleChange}
              className="w-full p-2 border rounded"
            />
          </div>
        )}
        <button
          type="submit"
          className="w-full p-3 text-white bg-blue-600 rounded-md hover:bg-blue-700"
        >
          Add House
        </button>
      </form>
    </div>
  );
};

export default AddHouse;
    