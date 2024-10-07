1)	USER DOCUMENTATION
# Overview

This project is a comprehensive ride-hailing service built on Flask, MongoDB, and SQLite3. It serves as a platform for users to efficiently order rides and for drivers to effectively manage and fulfill those orders. The application caters to distinct user and driver roles, offering tailored functionalities to meet their specific needs and enhance their experience.

## Features

1. **User Registration and Authentication:**
    - **User Registration:** New users can seamlessly sign up by providing essential details like username, email, password, and home address.
    - **Secure Authentication:** Passwords undergo rigorous bcrypt hashing to fortify security measures, safeguarding user credentials effectively.

2. **Driver Registration and Authentication:**
    - **Driver Registration:** Drivers have a comprehensive registration process where they provide username, email, password, detailed car information, license plate details, and their current location.
    - **Authentication for Drivers:** Drivers authenticate using a combination of an operation ID and password for secure access.

3. **Placing Orders:**
    - **User Orders:** Users have the flexibility to order rides by specifying departure and destination points, preferred car type, and providing payment information for a seamless transaction experience.
    - **Driver Acceptance:** Drivers can efficiently accept orders based on their vehicle type and availability, ensuring efficient ride allocation.

4. **Real-time Map View:**
    - Offers a dynamic map view for users waiting for a driver. This map displays active drivers nearby, enhancing the chances of quicker order acceptance and improving user experience.

5. **Order Management:**
    - **Driver Operations:** Drivers have a comprehensive dashboard to view pending orders, accept them, update order statuses in real-time, and mark orders as completed upon finishing rides.
    - **User Operations:** Users can effortlessly view their ongoing or completed orders, cancel pending orders, and access detailed invoices for completed rides.

6. **User and Driver History:**
    - Allows both users and drivers to access and review their respective order histories, facilitating better tracking and management of past rides.

7. **Real-time Chat Functionality:**
    - Offers a dedicated chat interface for users and drivers to communicate seamlessly in real-time, specifically designed for each order. This feature enhances coordination and addresses any concerns promptly during the ride.

## How to Use

1. **Registration:**
    - Users and drivers can register separately by filling out comprehensive sign-up forms, providing the required details.
    - Drivers need to upload license plate details for verification, enhancing the authentication process.

2. **Login:**
    - Users and drivers can log in securely using their registered email addresses and passwords.
    - Admin access is available with predefined credentials for administrative functions.

3. **Placing an Order:**
    - Users can effortlessly specify departure, destination, preferred car type, and payment details to book a ride seamlessly.

4. **Driver Operations:**
    - Drivers can efficiently manage their operations by viewing pending orders, accepting orders matching their vehicle type, marking orders as completed, and accessing their order history for better tracking.

5. **User Operations:**
    - Users have an intuitive interface to view ongoing or completed orders, cancel pending orders, and access detailed invoices for completed rides.

6. **Real-time Chat:**
    - Facilitates seamless real-time communication between users and drivers for each specific order, ensuring smooth coordination and addressing concerns during the ride promptly.

## Dependencies

- Flask
- Flask-Mail
- Flask-WTF
- Flask-SocketIO
- PyMongo
- SQLite3
- Bcrypt

## Running the Application

1. **Installation:**
    - Ensure all dependencies are installed and configured properly for smooth application functionality.

2. **Execution:**
    - Run the application by executing the main Python file in the terminal using the command `python app.py`.
    - Access the application through a web browser at `http://localhost:5000` for a seamless experience.

---

# Technical Documentation

## Overview

This application replicates the functionalities of a ride-hailing service like Uber. It's built using the Flask web framework in Python and integrates MongoDB for driver-related data and SQLite for user-related data. Real-time communication between users and drivers is facilitated by Socket.IO.

## Setup and Requirements

- **Python 3.7+:** Ensure Python is installed.
- **Dependencies:**
  - Flask: `pip install Flask`
  - MongoDB driver: `pip install pymongo`
  - SQLite (typically comes with Python)
  - Socket.IO: `pip install python-socketio`
  - Other Dependencies: `flask_mail`, `flask_login`, `wtforms`, `email_validator`, `folium`, `bcrypt`, `psutil`, `dotenv`.

## Components

1. **Main Components:**
    - **Flask App:** Initializes the Flask application, configures routes, templates, and extensions.
    - **MongoDB & SQLite:** MongoDB stores driver-related information; SQLite stores user-related data.
    - **SocketIO:** Enables real-time bidirectional event-based communication.
    - **Logging:** Captures performance metrics and errors.

2. **User Management:**
    - **Registration & Login:** Users and drivers can register and log in using distinct forms.
    - **User Object:** Represented by a common base class `User`, with extended classes for drivers and users.
    - **Password Encryption:** User passwords hashed using bcrypt before storing in the database.

3. **User Interface:**
    - **Templates:** HTML templates powered by Jinja2 for rendering user interfaces.
    - **Forms:** Flask-WTF forms used for user and driver registration/login.

4. **Functionalities:**
    - **User and Driver Registration:** Registration forms for users and drivers; data stored in SQLite and MongoDB respectively.
    - **Order Placement:** Users request rides by specifying departure, destination, and payment details.
    - **Driver Acceptance:** Drivers can accept user orders based on location and car type matching.
    - **Real-Time Updates:** Socket.IO updates order status in real-time.
    - **Order Completion & Invoicing:** Completed rides trigger email invoices to users and drivers.

5. **Routes and Functionality:**
    - `/signup` & `/login` Routes: Handles user and driver registration and login.
    - `/user_home` & `/driver_home` Routes: Provides user and driver homepages for order placement and viewing available orders.
    - `/accept_order` & `/complete_order` Routes: Routes to accept and complete user orders.
    - `/cancel_order` Route: Cancels user orders.
    - `/chat` Route: Facilitates communication between users and drivers for ongoing orders.
    - `/logout` Route: Handles user logout.

## Performance Monitoring

- **Request Performance Logging:** Logs request-response cycle times, memory usage, and response codes for each route.
- **Performance Log:** Stored in a file named `performance.log` for further analysis and troubleshooting.

## Deployment

- **Local Deployment:** The application runs locally on port 5000 using Socket.IO.
- **Configuration:**
  - **Environment Variables:** Store sensitive data (e.g., database credentials) in a `.env` file.
  - **Database Setup:** Configure MongoDB and SQLite connections in the `.env` file.

## Security Considerations

- **Input Sanitization:** Validate and sanitize user inputs to prevent SQL injection and XSS attacks.
- **Password Policies:** Implement strong password policies and encrypt stored passwords.
- **Secure Communication:** Use secure Socket.IO settings and encryption for communication.
- **Access Control:** Implement user roles and access control to restrict sensitive functionalities.

