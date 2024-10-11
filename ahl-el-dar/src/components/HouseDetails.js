// src/components/HouseDetails.js
import React from 'react';

const HouseDetails = ({ house }) => {
  return (
    <div className="border p-6 rounded-lg shadow-lg">
      <h2 className="text-2xl font-semibold mb-4">{house.address}</h2>
      <p><strong>Region:</strong> {house.region}</p>
      <p><strong>District:</strong> {house.district}</p>
      <p><strong>Town:</strong> {house.town}</p>
      <p><strong>Size:</strong> {house.size} sqm</p>
      <p><strong>Capacity:</strong> {house.capacity} people</p>
      <p><strong>Furnished:</strong> {house.furnished ? 'Yes' : 'No'}</p>
      <p><strong>Contact:</strong> {house.phone_number}</p>
      {house.for_rent ? (
        <p><strong>Rent:</strong> ${house.rent_amount} per month</p>
      ) : (
        <p><strong>Status:</strong> Available for free</p>
      )}
      <div className="mt-4">
        <h3 className="text-lg font-semibold">Photos:</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {house.photos && house.photos.map((photo, index) => (
            <img key={index} src={photo} alt="House" className="rounded-md shadow-sm" />
          ))}
        </div>
      </div>
    </div>
  );
};

export default HouseDetails;
