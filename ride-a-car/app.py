"""
Final project
"""
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FileField
from wtforms.validators import InputRequired, Length, Email, EqualTo
from email_validator import validate_email, EmailNotValidError
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user, login_manager, login_required
from pymongo import MongoClient
from dotenv import load_dotenv
from flask_socketio import SocketIO, emit
import logging
import os
from bson.objectid import ObjectId
import sqlite3
from utils import *
from flask_wtf.file import FileAllowed
import datetime
import folium
import uuid
import time
import psutil
import bcrypt



app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# Load environment variables from .env file
load_dotenv()

# Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = os.getenv('MAIL_PORT')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

mail = Mail(app)
socketio = SocketIO(app)

# MongoDB Configuration
mongo_client = MongoClient(os.getenv('MONGO_URI'))
mongo_db = mongo_client['uber_db']
drivers_collection = mongo_db['drivers']
orders_collection = mongo_db['orders']

logger = logging.getLogger('performance_logger')
logger.setLevel(logging.INFO)

# Create a file handler
file_handler = logging.FileHandler('performance.log')
file_handler.setLevel(logging.INFO)

# Create a formatter and add it to the handler
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the file handler to the logger
logger.addHandler(file_handler)

# SQLite3 Configuration
conn = sqlite3.connect('uber_users.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        location TEXT NOT NULL
    )
''')
conn.commit()

def insert_admin():
    admin = cursor.execute("SELECT * FROM users WHERE username = ?", ('admin',))
    if admin.fetchone() is None:
        cursor.execute("INSERT INTO users (username, email, password, location) VALUES (?, ?, ?, ?)", ('admin', 'admin@admin.com', 'admin_password', 'my address'))
        conn.commit()
    else: 
        return
insert_admin()

class User(UserMixin):
    def __init__(self, id, username, email, password, location, is_driver=False):
        """
        Initializes a User object.

        Args:
            id (int): The user's ID.
            username (str): The user's username.
            email (str): The user's email address.
            password (str): The user's password.
            location (str): The user's location.
            is_driver (bool, optional): Indicates if the user is a driver. Defaults to False.
        """
        self.id = id
        self.username = username
        self.email = email
        self.password = password
        self.location = location
        self.is_driver = is_driver

    def get_id(self):
        """
        Returns the user's ID.

        Returns:
            int: The user's ID.
        """
        return self.id

    def update_location(self, new_location):
        """
        Updates the user's location.

        Args:
            new_location (str): The new location to be updated.
        """
        self.location = new_location


# Function to generate a unique driver ID based on the username
def generate_driver_id(username):
    """
    Generates a unique driver ID based on the username.

    Args:
        username (str): The username of the driver.

    Returns:
        str: The generated driver ID.
    """
    first_letters = username[0].upper() + username[1].upper()
    count = drivers_collection.count_documents({})
    operation_id = f"{first_letters}_{count}_{str(uuid.uuid4())[:8]}"  # Using UUID for uniqueness
    return operation_id


# Function to send a confirmation email to the driver
def send_driver_confirmation_email(email, username, operation_id):
    """
    Sends a confirmation email to the driver.

    Args:
        email (str): The email address of the driver.
        username (str): The username of the driver.
        operation_id (str): The operation ID of the driver.

    Returns:
        None
    """
    try:
        # Send email to driver
        driver_email = email  # Replace `get_driver_email` with the actual function to get driver's email
        driver_msg = Message('Registration Confirmation', sender='uber-registration@noreply.com', recipients=[driver_email])
        driver_msg.body = f'Welcome {username} to our platform! Your operation ID is {operation_id}.'

        mail.send(driver_msg)
        app.logger.info(f'Email sent to driver: {driver_email}')
    except Exception as e:
        flash('Error while sending email', 'error')
        app.logger.error(f'Error while sending email: {e}')
    
# Function to send a confirmation email to the user
def send_user_confirmation_email(email, username):
    """
    Sends a confirmation email to the user.

    Args:
        email (str): The email address of the user.
        username (str): The username of the user.

    Returns:
        None
    """
    try:
        # Send email to user
        user_msg = Message('Registration Confirmation', sender='uber-registration@noreply.com', recipients=[email])
        user_msg.body = f'Welcome {username} to our platform! Thank you for registering.'

        mail.send(user_msg)
        app.logger.info(f'Email sent to user: {email}')
    except Exception as e:
        flash('Error while sending email', 'error')
        app.logger.error(f'Error while sending email: {e}')

# Function to send an invoice email to the user
def send_invoice_email_user(email, order):
    """
    Sends an invoice email to the specified email address with the details of the order.

    Args:
        email (str): The email address of the recipient.
        order (dict): A dictionary containing the details of the order.

    Returns:
        None
    """
    try:
        # Customize the subject and body of the invoice email as needed
        invoice_subject = 'Invoice for your order'
        invoice_body = f"Dear customer,\n\nHere's the invoice for your recent order:\nOrder ID: {order['_id']}\nTime Placed: {order['time_placed']}\nTime completed: {order['time_completed']}\nTotal Amount: {order['price']}\n\nThank you for choosing our service!"
        
        invoice_msg = Message(invoice_subject, sender='order-invoice@noreply.com', recipients=[email])
        invoice_msg.body = invoice_body

        mail.send(invoice_msg)
        app.logger.info(f'Invoice email sent to user: {email}')
    except Exception as e:
        flash('Error while sending invoice email', 'error')
        app.logger.error(f'Error while sending invoice email: {e}')

# Function to send an invoice email to the driver
def send_invoice_email_driver(email, order):
    """
    Sends an invoice email to the specified email address with the details of the order.

    Args:
        email (str): The email address of the recipient.
        order (dict): A dictionary containing the details of the order.

    Returns:
        None
    """
    try:
        # Customize the subject and body of the invoice email as needed
        invoice_subject = 'Invoice for your order'
        invoice_body = f"Dear driver,\n\nHere's the invoice for your recent order:\nOrder ID: {order['_id']}\nTime Placed: {order['time_placed']}\nTime completed: {order['time_completed']}\nYour pay: {order['price']}\n\nKeep up!"
        
        invoice_msg = Message(invoice_subject, sender='order-invoice@noreply.com', recipients=[email])
        invoice_msg.body = invoice_body

        mail.send(invoice_msg)
        app.logger.info(f'Invoice email sent to driver: {email}')
    except Exception as e:
        flash('Error while sending invoice email', 'error')
        app.logger.error(f'Error while sending invoice email: {e}')

# forms using Flask-WTF
class UserRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    location = StringField('Home Address', validators=[InputRequired(), Length(min=10, max=200)])

class DriverRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    car_brand = StringField('Car Brand', validators=[InputRequired()])
    car_type = StringField('Car Type', validators=[InputRequired()])
    car_color = StringField('Car Color', validators=[InputRequired()])
    location = StringField('Location', validators=[InputRequired(), Length(min=10, max=200)])
    license_plate = FileField('Upload License Plate', validators=[InputRequired(), FileAllowed(['jpg', 'jpeg', 'png', 'pdf'], 'Only JPG, JPEG, PDF and PNG files are allowed.')])

class UserLoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

class DriverLoginForm(FlaskForm):
    operation_id = StringField('Operation ID (provided on sign in)', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])


@app.before_request
def before_request():
    request.start_time = time.time()
    if current_user and current_user.is_authenticated:
        if current_user.is_driver:
            session['is_driver'] = True
            session.pop('is_user', None)
        else:
            session['is_user'] = True
            session.pop('is_driver', None)

route_performances = []

# This code block defines an after_request function that is executed after each request.
# It calculates the time taken for the request, the memory usage, and the response code.
# It logs the performance metrics and appends them to the route_performances list.
@app.after_request
def after_request(response):
    if hasattr(request, 'start_time'):
        request_time = time.time() - request.start_time
        route = request.path
        method = request.method

        memory_usage = psutil.Process(os.getpid()).memory_info().rss / 1024 ** 2  # in MB

        perfomance = {
            'route': route,
            'method': method,
            'time_taken': round(request_time, 4),
            'memory_usage': round(memory_usage, 2),
            'response_code': response.status_code,
        }

        route_performances.append(perfomance)
        logger.info(perfomance)

    return response

# This code block defines a user_loader function for the login manager.
# It is responsible for loading the user object from the session based on the user_id.
# It checks the session variables 'is_user' and 'is_driver' to determine the type of user.
# If the user is a driver, it retrieves the driver information from the drivers_collection.
# If the user is not a driver, it retrieves the user information from the 'users' table.
@login_manager.user_loader
def load_user(user_id):
    # Use separate keys for user and driver sessions
    is_user = session.get('is_user')
    is_driver = session.get('is_driver')

    if is_driver:
        driver = drivers_collection.find_one({'_id': ObjectId(user_id)})
        if driver:
            return User(driver['_id'], driver['username'], driver['email'], driver['password'], driver['location'], is_driver=True)
    elif is_user:
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            id, username, email, password, location = user
            return User(id, username, email, password, location, is_driver=False)
    
    return None

# Route for handling the index page
@app.route('/')
def index():
    # TODO: Render the index.html template
    return render_template('index.html')

# Route for handling registration
@app.route('/signup', methods=['GET', 'POST'])
def sign_up():
    user_form = UserRegistrationForm()
    driver_form = DriverRegistrationForm()

    if request.method == 'POST':
        if 'user_submit' in request.form and user_form.validate_on_submit():
            # Handle user registration (SQLite)
            username = user_form.username.data
            email = user_form.email.data
            password_raw = user_form.password.data
            location = user_form.location.data
            password = bcrypt.hashpw(password_raw.encode('utf-8'), bcrypt.gensalt())
            try:
                cursor.execute("INSERT INTO users (username, email, password, location) VALUES (?, ?, ?, ?)", (username, email, password, location))
                conn.commit()

                # Send email to the provided email address
                send_user_confirmation_email(email, username)

                flash('User registered successfully', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username or email already exists', 'error')

        elif 'driver_submit' in request.form and driver_form.validate_on_submit():
            # Handle driver registration (MongoDB)
            username = driver_form.username.data
            email = driver_form.email.data
            password_raw2 = driver_form.password.data
            password = bcrypt.hashpw(password_raw2.encode('utf-8'), bcrypt.gensalt())
            car_brand = driver_form.car_brand.data
            car_type = driver_form.car_type.data
            car_color = driver_form.car_color.data
            license_plate = request.files['license_plate']
            operation_id = generate_driver_id(username)
            location = driver_form.location.data
            longitude = get_coordinates(location)[0]
            latitude = get_coordinates(location)[1]

            if drivers_collection.find_one({'username': username}):
                flash('Username already exists', 'error')
                return redirect(url_for('sign_up'))
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if user:
                flash('Username already exists', 'error')
                return redirect(url_for('sign_up'))
            driver_data = {
                'username': username,
                'email': email,
                'password': password,
                'car brand': car_brand,
                'car type': car_type,
                'car color': car_color,
                'license plate data': license_plate.read(),
                'rating': 0,
                'status': 'Registered',
                'operation_id': operation_id,
                'location': location,
                'longitude': longitude,
                'latitude': latitude
            }
            drivers_collection.insert_one(driver_data)

            # Send email to the provided email address
            send_driver_confirmation_email(email, username, operation_id)
            message = "Driver registered successfully, your ID is " +  str(operation_id)

            flash(message)
            return redirect(url_for('login'))

    return render_template('sign_up.html', user_form=user_form, driver_form=driver_form, car_brands=car_brands, car_types=car_types, car_colors=car_colors)


# Route for handling login
@app.route('/login', methods=['GET', 'POST'])
def login():
    user_form = UserLoginForm()
    driver_form = DriverLoginForm()

    if request.method == 'POST':
        if 'user_submit' in request.form and user_form.validate_on_submit():
            # Handle user login (SQLite)
            email = user_form.email.data
            password_raw = user_form.password.data

            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            if user and user[1] == 'admin' and user[3] == 'admin_password':
                login_user(User(user[0], user[1], user[2], user[3], user[4], is_driver=False))
                session['is_user'] = True
                flash('Admin logged in successfully', 'success')
                return redirect(url_for('admin_dashboard'))

            if user and bcrypt.checkpw(password_raw.encode('utf-8'), user[3]):  # Assuming password is in the 4th column
                user_object = User(user[0], user[1], user[2], user[3], user[4], is_driver=False)
                login_user(user_object)
                current_user.update_location(user[4])
                session['is_user'] = True
                flash('User logged in successfully', 'success')
                return redirect(url_for('user_home'))
            else:
                flash('Incorrect email or password', 'error')

        elif 'driver_submit' in request.form and driver_form.validate_on_submit():
            # Handle driver login (MongoDB)
            operation_id = driver_form.operation_id.data
            password_raw2 = driver_form.password.data   

            driver = drivers_collection.find_one({'operation_id': operation_id})
            drivers_collection.update_one({'operation_id': operation_id}, {'$set': {'status': 'Active'}})

            if driver and bcrypt.checkpw(password_raw2.encode('utf-8'), driver['password']):
                driver_object = User(
                    str(driver['_id']),  # Assuming '_id' is the driver's unique identifier
                    driver['username'],
                    driver['email'],
                    driver['password'],
                    driver['location'],
                    is_driver=True
                )
                login_user(driver_object)
                session['is_driver'] = True
                flash('Driver logged in successfully', 'success')
                return redirect(url_for('driver_home'))
            else:
                flash('Incorrect operation ID or password', 'error')

    return render_template('login.html', user_form=user_form, driver_form=driver_form)
# Route for handling the admin dashboard
@app.route('/admin')
@login_required
def admin_dashboard():
    # Render the admin_dashboard.html template and pass the performance_data to it
    return render_template('admin_dashboard.html', perfomance_data=route_performances)

# Route for handling user home
@app.route('/user_home', methods=['GET', 'POST'])
@login_required
def user_home():
    if request.method == 'POST':
        departure = request.form['departure']
        destination = request.form['destination']
        time = str(datetime.datetime.now().strftime("%Y-%m-%d ")) + str(request.form['time'])
        car_type = request.form['car_type']
        card_number = request.form['card_number']
        cvv = request.form['cvv']
        expiration_date = str(request.form['expiration_date'])
        if 'order_submit' in request.form:
                coordinates1 = get_coordinates(departure)
                session['user_location'] = departure
                coordinates2 = get_coordinates(destination)
                distance, price = calc_distance_price_for_run(coordinates1[0], coordinates1[1], coordinates2[0], coordinates2[1])
                order_data = {
                    'username': current_user.username,
                    'driver': 'Not Assigned',
                    'order number': orders_collection.count_documents({}) + 1,
                    'departure_Ad': departure,
                    'destination_Ad': destination,
                    'departure': coordinates1,
                    'destination': coordinates2,
                    'time_placed': time,
                    'time_completed': None,
                    'car type': car_type,
                    'distance': str(distance)+' km',
                    'price': str(price)+' £',
                    'status': 'Pending',
                    'payement_info': [card_number, cvv, expiration_date] 
                }
                orders_collection.insert_one(order_data)
                session['user_location'] = departure
                current_user.update_location(departure)
                flash('Order placed successfully', 'success')
                socketio.emit('order_placed', {'order_id': str(order_data['_id'])})
                return redirect(url_for('wait_for_driver'))
        else:
            flash('Order not placed', 'error')
    return render_template('user_home.html', car_types=car_types, user=current_user)

# Route for handling the waiting for driver page
@app.route('/wait_for_driver')
@login_required
def wait_for_driver():
    user_area = session.get('user_location')
    user_long, user_lat = get_coordinates(user_area)

    map_obj = folium.Map(location=[user_lat, user_long], zoom_start=10)

    # Marker for current user's location
    folium.Marker(
        location=[user_lat, user_long],
        popup='Your location',
        icon=folium.Icon(color='green', icon='person', icon_color='white')
    ).add_to(map_obj)

    # Get active drivers and add markers for them
    active_drivers = drivers_collection.find({'status': 'Active'})

    for driver in active_drivers:
        distance_from_user, _ = calc_distance_price_for_run(user_long, user_lat, driver['longitude'], driver['latitude'])
        popup_content = f"Driver: {driver['username']}<br>Status: {driver['status']}<br>Vehicle Type: {driver['car type']}<br>Rating: {driver['rating']}<br>Distance from you: {distance_from_user}km"
        driver_location = [driver['latitude'], driver['longitude']]

        folium.Marker(
            location=driver_location,
            popup=folium.Popup(popup_content, max_width=300),
            icon=folium.Icon(color="blue", icon='car', icon_color='white')
        ).add_to(map_obj)


    return render_template('waiting_for_driver.html', map=map_obj._repr_html_())

# Route for handling order cancellation
@app.route('/cancel_order')
def cancel_order():
    orders_collection.delete_one({'username': current_user.username, 'status': 'Pending'})
    socketio.emit('order_cancelled', {'username': current_user.username})
    return redirect(url_for('user_home'))

# Route for handling the driver home
@app.route('/driver_home')
@login_required
def driver_home():
    driver = drivers_collection.find_one({'username': current_user.username})
    area = driver['location']
    long, lat = get_coordinates(area)
    map_obj = folium.Map(location=[lat, long], zoom_start=10)
    folium.Marker(
        location=[lat, long],
        popup='Your location',
        icon=folium.Icon(color='green', icon='person')
    ).add_to(map_obj)
    
    orders = orders_collection.find({})
    you = drivers_collection.find_one({'username': current_user.username})
    
    for order in orders:
        if order['driver'] == 'Not Assigned' and order['status'] == 'Pending':
            if order['car type'] == you['car type']:
                popup_content = f"Username: {order['username']}<br>Departure: {order['departure_Ad']}<br>Destination: {order['destination_Ad']}<br>Time Placed: {order['time_placed']}<br>Car Type: {order['car type']}<br>Distance of the ride: {order['distance']}<br>Price: {order['price']}<br><button onclick='parent.acceptOrder(\"{str(order['_id'])}\")'>Accept Order</button>"
                marker = {
                    'location': [order['departure'][1], order['departure'][0]],
                    'popup_content': popup_content,
                    'status': order['status'],
                    'order_id': str(order['_id'])  # Include order ID in markers_data
                }
                folium.Marker(
                    location=marker['location'],
                    popup=folium.Popup(marker['popup_content'], max_width=300),
                    icon=folium.Icon(icon='person', icon_color='white')
                ).add_to(map_obj)
    return render_template('driver_home.html', map=map_obj._repr_html_())

@app.route('/accept_order/<order_id>', methods=['POST'])
def accept_order(order_id):
    orders_collection.update_one({'_id': ObjectId(order_id)}, {'$set': {'status': 'Accepted', 'driver': current_user.username}})
    # Emitting a socket event to notify the user about the accepted order
    socketio.emit('order_accepted', {'order_id': str(order_id)})  # Notify the user with the order ID
    
    return jsonify({'success': True})

# Route for handling the ongoing journey
@app.route('/ongoing_journey/<order_id>')
@login_required
def ongoing_journey(order_id):
    orders_collection.update_one({'_id': ObjectId(order_id)}, {'$set': {'status': 'Ongoing'}})
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    driver_location = order['departure_Ad']
    drivers_collection.update_one({'username': current_user.username}, {'$set': {'location': driver_location}})
    long, lat = get_coordinates(driver_location)
    drivers_collection.update_one({'username': current_user.username}, {'$set': {'longitude': long, 'latitude': lat}})
    long2, lat2 = get_coordinates(order['destination_Ad'])
            # Create the map object
    map_obj = folium.Map(location=[lat, long], zoom_start=10)

            # Add markers for departure and destination
    folium.Marker(
        location=[lat, long],
        popup='Driver Location',
        icon=folium.Icon(color='green', icon='person')
    ).add_to(map_obj)

    folium.Marker(
        location=[lat2, long2],
        popup='Destination',
        icon=folium.Icon(color='red', icon='flag')
    ).add_to(map_obj)

    return render_template('ongoing_journey.html', map=map_obj._repr_html_(), order_id=str(order_id))

# Route for handling the order completion
@app.route('/complete_order/<order_id>', methods=['GET', 'POST'])
@login_required
def complete_order(order_id):
    orders_collection.update_one({'_id': ObjectId(order_id)}, {'$set': {'status': 'Completed', 'time_completed': str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))}})
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    driver_location = order['destination_Ad']
    drivers_collection.update_one({'username': current_user.username}, {'$set': {'location': driver_location}})
    long, lat = get_coordinates(driver_location)
    drivers_collection.update_one({'username': current_user.username}, {'$set': {'longitude': long, 'latitude': lat}})
    cursor.execute("UPDATE users SET location = ? WHERE username = ?", (driver_location, order['username']))
    socketio.emit('order_completed', {'order_id': str(order_id)})
    return jsonify({'success': True})

# Route for handling the driver invoice
@app.route('/driver_invoice/<order_id>')
@login_required
def driver_invoice(order_id):
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    send_invoice_email_driver(current_user.email, order)
    return render_template('driver_invoice.html', order=order)

# Route for handling the user invoice
@app.route('/user_invoice/<order_id>/<lang>', methods=['POST', 'GET'])
@login_required
def user_invoice(order_id, lang):
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    send_invoice_email_user(current_user.email, order)
    return render_template('user_invoice.html', order=order, lang=lang)

# Route for handling the rating of the driver
@app.route('/rate_driver/<driver>/<rating>', methods=['POST'])
@login_required
def rate_driver(driver, rating):
    print("route reached")
    result = drivers_collection.update_one({'username': driver}, {'$set': {'rating': rating}})
    if result.modified_count == 1:    
        return jsonify({'success': True})
    else:
        return jsonify({'success': False})

# Route for handling the driver history
@app.route('/driver_history')
@login_required
def driver_history():
    completed_orders = orders_collection.find({'driver': current_user.username, 'status': 'Completed'})
    return render_template('driver_history.html', completed_orders=completed_orders)

# Route for handling the user history
@app.route('/user_history')
@login_required
def user_history():
    completed_orders = orders_collection.find({'username': current_user.username, 'status': 'Completed'})
    return render_template('user_history.html', completed_orders=completed_orders)

# Route for handling the getting of user role
@app.route('/get_user_role')
def get_user_role():
    current_user = load_user(session.get('user_id'))

    if current_user and current_user.is_driver:
        return jsonify({'role': 'driver'})
    else:
        return jsonify({'role': 'user'})

# Route for the chat interface
@app.route('/chat/<order_id>')
@login_required
def chat(order_id):
    order = orders_collection.find_one({'_id': ObjectId(order_id)})
    return render_template('chat.html', order=order)

# New Socket.IO event for handling chat messages
@socketio.on('chat_message')
def handle_message(data):
    message = data['message']
    sender = current_user.username # Change this to get the actual sender information

    # Emit the message along with the sender information
    emit('chat_message', {'message': message, 'sender': sender}, broadcast=True)

# Route for handling the logout
@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        if current_user.is_driver:
            session.pop('is_driver', None)
        else:
            session.pop('is_user', None)
        logout_user()

    return redirect(url_for('login'))




if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)
