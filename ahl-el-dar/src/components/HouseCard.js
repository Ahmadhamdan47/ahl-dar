// src/components/HouseCard.js
import React from 'react';

const HouseCard = ({ house, onClick }) => {
  return (
    <div className="border p-4 rounded-lg shadow-lg cursor-pointer" onClick={onClick}>
      <h2 className="text-xl font-semibold">{house.address}</h2>
      <p>{house.region}, {house.district}, {house.town}</p>
      <p>Size: {house.size} sqm</p>
      <p>Capacity: {house.capacity} people</p>
      <p>Furnished: {house.furnished ? 'Yes' : 'No'}</p>
      {house.for_rent ? (
        <p>Rent: ${house.rent_amount}</p>
      ) : (
        <p>This house is available for free.</p>
      )}
    </div>
  );
};

export default HouseCard;
