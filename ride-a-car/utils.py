import requests
from requests.structures import CaseInsensitiveDict
from math import *

# List of available car brands, types, and colors
car_brands = ['Tesla', 'Toyota', 'Ford', 'BMW', 'Honda', 'Mercedes-Benz', 'Audi', 'Chevrolet', 'Volkswagen', 'Nissan']
car_types = ['Sedan', 'SUV', 'Hatchback', 'Coupe', 'Convertible', 'Truck', 'Van', 'Wagon', 'Electric', 'Hybrid']
car_colors = ['Black', 'White', 'Silver', 'Gray', 'Red', 'Blue', 'Green', 'Brown', 'Yellow', 'Orange']

def get_coordinates(address):
    """Retrieve longitude and latitude coordinates for a given address using Geoapify API."""
    
    # API endpoint for retrieving coordinates based on the provided address
    url = f"https://api.geoapify.com/v1/geocode/search?text={address}&apiKey=7e9993186a624b68bc6bc55d15d276bf"
    coordinates = None

    headers = CaseInsensitiveDict()
    headers["Accept"] = "application/json"

    # Sending a GET request to Geoapify API to retrieve data
    resp = requests.get(url, headers=headers)
    data = resp.json()

    # Extracting longitude and latitude if available
    if "features" in data and len(data["features"]) > 0:
        longitude = data["features"][0]["properties"]["lon"]
        latitude = data["features"][0]["properties"]["lat"]
        coordinates = [longitude, latitude]
        return coordinates
    else:
        return None


def calc_distance_price_for_run(long1, lat1, long2, lat2):
    """Calculate the distance and price between two sets of longitude and latitude coordinates."""
    
    # Price per kilometer
    price_per_km = 1.5
    R = 6371.0  # Earth's radius in kilometers
    
    # Converting degrees to radians for trigonometric calculations
    lat1_rad = radians(lat1)
    lon1_rad = radians(long1)
    lat2_rad = radians(lat2)
    lon2_rad = radians(long2)
    
    # Calculating differences in latitude and longitude
    dlat = lat2_rad - lat1_rad
    dlon = lon2_rad - lon1_rad
    
    # Haversine formula for calculating distance between two points on Earth's surface
    a = sin(dlat / 2)**2 + cos(lat1_rad) * cos(lat2_rad) * sin(dlon / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))
    distance = R * c
    
    # Rounding distance and calculating price based on distance traveled
    distance = round(distance, 2)
    price = price_per_km * distance
    price = round(price, 2)
    
    return distance, price
