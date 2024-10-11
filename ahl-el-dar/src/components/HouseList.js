// src/components/HouseList.js
import React, { useEffect, useState } from 'react';
import axios from 'axios';
import HouseCard from './HouseCard';
import HouseDetails from './HouseDetails'; // Ensure this is imported

const HouseList = () => {
  const [houses, setHouses] = useState([]);
  const [selectedHouse, setSelectedHouse] = useState(null);

  useEffect(() => {
    // Fetch houses from the backend
    const fetchHouses = async () => {
      try {
        const response = await axios.get('http://localhost:3000/houses');
        setHouses(response.data);
      } catch (error) {
        console.error('Error fetching houses:', error);
      }
    };

    fetchHouses();
  }, []);

  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-2xl font-semibold mb-6">Available Houses</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {houses.map((house) => (
          <HouseCard
            key={house.id}
            house={house}
            onClick={() => setSelectedHouse(house)}
          />
        ))}
      </div>
      {selectedHouse && (
        <div className="mt-8">
          {/* Show detailed house information */}
          <HouseDetails house={selectedHouse} />
        </div>
      )}
    </div>
  );
};

export default HouseList;
