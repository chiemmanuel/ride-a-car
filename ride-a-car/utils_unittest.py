import unittest
from unittest.mock import patch, MagicMock
from utils import get_coordinates, calc_distance_price_for_run

class TestUtils(unittest.TestCase):
    """A test class for utility functions in the application."""

    def test_get_coordinates(self):
        """Test case for get_coordinates function."""

        # Mocking the requests.get function and its response
        with patch('utils.requests.get') as mock_get:
            # Mocking a valid response
            mock_response = MagicMock()
            mock_response.json.return_value = {
                "features": [
                    {
                        "properties": {
                            "lon": 2.349014,
                            "lat": 48.864716
                        }
                    }
                ]
            }
            mock_get.return_value = mock_response

            # Testing with a valid address
            address = "sample address"
            result = get_coordinates(address)
            self.assertEqual(result, [2.349014, 48.864716])

            # Testing with an invalid response
            mock_response.json.return_value = {}
            result = get_coordinates(address)
            self.assertIsNone(result)

    def test_calc_distance_price_for_run(self):
        """Test case for calc_distance_price_for_run function."""

        # Test case for calculating distance and price
        long1, lat1 = 10.0, 20.0
        long2, lat2 = 30.0, 40.0
        expected_distance = 2927.39
        expected_price = 4391.09

        distance, price = calc_distance_price_for_run(long1, lat1, long2, lat2)
        self.assertAlmostEqual(distance, expected_distance, places=2)
        self.assertAlmostEqual(price, expected_price, places=2)


if __name__ == '__main__':
    unittest.main()
