# Extended Flask App for MedTrack
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import uuid
from functools import wraps
from dotenv import load_dotenv
from boto3.dynamodb.conditions import Attr
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

# Load environment variables
load_dotenv()


# ---------- Email Configuration ----------
ENABLE_EMAIL = os.getenv("ENABLE_EMAIL", "false").lower() == "true"
SENDER_EMAIL = os.getenv("SENDER_EMAIL")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD")
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))

# ---------- SNS Configuration ----------
ENABLE_SNS = os.getenv("ENABLE_SNS", "false").lower() == "true"
SNS_TOPIC_ARN = os.getenv("SNS_TOPIC_ARN")
sns = boto3.client("sns", region_name=os.getenv("AWS_REGION_NAME", "ap-south-1"))


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key")

@app.context_processor
def inject_now():
    return {'now': datetime.now()}



# Load configuration from environment
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'ap-south-1')
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'UsersTable')
APPOINTMENTS_TABLE_NAME = os.environ.get('APPOINTMENTS_TABLE_NAME', 'AppointmentsTable')
NOTIFICATIONS_TABLE_NAME = os.environ.get('NOTIFICATIONS_TABLE_NAME', 'NotificationsTable')
DIAGNOSES_TABLE_NAME = os.environ.get('DIAGNOSES_TABLE_NAME', 'DiagnosesTable')

try:
    dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
    user_table = dynamodb.Table(USERS_TABLE_NAME)
    appointment_table = dynamodb.Table(APPOINTMENTS_TABLE_NAME)
    notification_table = dynamodb.Table(NOTIFICATIONS_TABLE_NAME)
    diagnosis_table = dynamodb.Table(DIAGNOSES_TABLE_NAME)
    DYNAMO_ENABLED = True
except (NoCredentialsError, PartialCredentialsError, Exception) as e:
    DYNAMO_ENABLED = False
    user_table = None
    appointment_table = None
    notification_table = None
    diagnosis_table = None
    logging.error("❌ Failed to connect to DynamoDB. Check AWS credentials and table names.")
    logging.error(f"Exception: {e}")




# ---------- DynamoDB Storage Helpers ----------

def save_user_dynamodb(user_id, user_data):
    user_table.put_item(Item={
        'user_id': user_id,
        'name': user_data['name'],
        'email': user_data['email'],
        'password': user_data['password'],
        'role': user_data['role'],
        'age': user_data['extra'].get('age'),
        'gender': user_data['extra'].get('gender'),
        'address': user_data['extra'].get('address'),
        'specialization': user_data['extra'].get('specialization'),
        'experience': user_data['extra'].get('experience'),
        'medical_history': user_data['extra'].get('medical_history')
    })


def get_user_by_email_dynamodb(email):
    try:
        response = user_table.scan(
            FilterExpression=Attr('email').eq(email)
        )
        items = response.get('Items', [])
        if items:
            user = items[0]
            return user['user_id'], {
                'name': user['name'],
                'email': user['email'],
                'password': user['password'],
                'role': user['role'],
                'extra': {
                    'age': user.get('age'),
                    'gender': user.get('gender'),
                    'address': user.get('address'),
                    'specialization': user.get('specialization'),
                    'experience': user.get('experience'),
                    'medical_history': user.get('medical_history')
                }
            }
    except Exception as e:
        logging.error(f"Error retrieving user by email from DynamoDB: {e}")

    return None, None


# ---------- Logging Setup ----------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()  # Allows real-time log output to console/EC2 logs
    ]
)


# ---------- Helper Functions ----------

def is_logged_in():
    return 'email' in session

def get_user_role(email):
    try:
        # Use scan because 'email' is not the primary key (user_id is)
        response = user_table.scan(
            FilterExpression=Attr('email').eq(email)
        )
        items = response.get('Items', [])
        if items:
            return items[0].get('role')
    except Exception as e:
        logging.error(f"Error fetching role for {email}: {e}")
    return None

def send_email(to_email, subject, message):
    if not ENABLE_EMAIL:
        logging.info(f"[Email Skipped] Subject: {subject} to {to_email}")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(message, 'html'))

        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)

        logging.info(f"Email sent to {to_email}")
    except Exception as e:
        logging.error(f"Email failed to send: {e}")

def publish_to_sns(message, subject="MedTrack Notification"):
    if not ENABLE_SNS:
        logging.info(f"[SNS Skipped] Subject: {subject}")
        return

    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        logging.info(f"SNS published: {response['MessageId']}")
    except Exception as e:
        logging.error(f"SNS publish failed: {e}")



# ---------- Utility: Role Required Decorator ----------

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'userid' not in session or session.get('role') != role:
                logging.warning(f"Unauthorized access attempt. Required role: {role}, session role: {session.get('role')}")
                flash("Unauthorized access.", "danger")
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ---------- Storage Abstraction ----------

def save_user(user_id, user_data):
    save_user_dynamodb(user_id, user_data)

def get_user_by_email(email):
    return get_user_by_email_dynamodb(email)


# ---------- Routes ----------
# ---------- Home Page ----------

@app.route('/')
def index():
    if is_logged_in():
        role = get_user_role(session['email'])
        if role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif role == 'patient':
            return redirect(url_for('patient_dashboard'))
        else:
            logging.warning(f"Logged-in user with unknown role: {role}")
            flash("Unknown user role. Please contact support.", "warning")
            return redirect(url_for('logout'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Required fields
        required_fields = ['name', 'email', 'password', 'role']
        for field in required_fields:
            value = request.form.get(field, '').strip()
            if not value:
                flash(f'Please fill in the {field} field.', 'danger')
                return render_template('register.html')

        if request.form['password'] != request.form.get('confirm_password', ''):
            flash("Passwords do not match.", 'danger')
            return render_template('register.html')

        email = request.form['email'].strip().lower()

        # ✅ Corrected: Email is not partition key; use scan
        try:
            response = user_table.scan(
                FilterExpression=Attr('email').eq(email)
            )
            items = response.get('Items', [])
            if items:
                flash('Email already registered.', 'danger')
                return render_template('register.html')
        except Exception as e:
            logging.error(f"Error checking email uniqueness: {e}")
            flash('An error occurred. Please try again.', 'danger')
            return render_template('register.html')

        # Role-specific fields
        role = request.form['role']
        age = request.form.get('patient_age') if role == 'patient' else request.form.get('doctor_age')
        gender = request.form.get('patient_gender') if role == 'patient' else request.form.get('doctor_gender')

        if not age or not age.strip():
            flash("Please fill in the age field.", 'danger')
            return render_template('register.html')

        if not gender or not gender.strip():
            flash("Please select a gender.", 'danger')
            return render_template('register.html')

        # Generate unique user ID
        generated_id = f"{role[:3].upper()}{str(uuid.uuid4())[:5]}"

        # Build user data
        user_data = {
            'user_id': generated_id,
            'name': request.form['name'].strip(),
            'email': email,
            'password': generate_password_hash(request.form['password']),
            'role': role,
            'extra': {
                'age': age.strip(),
                'gender': gender,
                'address': request.form.get('address', '').strip(),
                'specialization': request.form.get('specialization', '').strip(),
                'experience': request.form.get('experience', '').strip(),
                'medical_history': request.form.get('medical_history', '').strip()
            }
        }

        # Save to DynamoDB
        try:
            user_table.put_item(Item=user_data)
        except Exception as e:
            logging.error(f"Error saving user to DynamoDB: {e}")
            flash("Could not register. Please try again later.", 'danger')
            return render_template('register.html')

        # Send welcome email
        if ENABLE_EMAIL:
            welcome_msg = f"""
                <h2>Welcome to MedTrack, {user_data['name']}!</h2>
                <p>Your registration was successful.</p>
                <p>User ID: <strong>{generated_id}</strong></p>
            """
            send_email(user_data['email'], "Welcome to MedTrack", welcome_msg)

        # SNS notification
        if ENABLE_SNS and sns:
            try:
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Message=f"New user registered: {user_data['name']} ({user_data['email']}) as {user_data['role']}",
                    Subject="New Registration - MedTrack"
                )
            except Exception as e:
                logging.error(f"SNS publish failed: {e}")

        logging.info(f"User registered: {generated_id}")
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        role = session.get('role')
        return redirect(url_for(f'{role}_dashboard'))

    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        selected_role = request.form['role']

        if not email or not password or not selected_role:
            flash("All fields are required.", 'danger')
            return render_template('login.html')

        user_id, user = get_user_by_email(email)

        if user_id and check_password_hash(user['password'], password):
            actual_role = user['role']
            if actual_role != selected_role:
                flash("Role mismatch! Please select the correct role for your account.", 'danger')
                logging.warning(f"Role mismatch for email: {email} (selected: {selected_role}, actual: {actual_role})")
                return redirect(url_for('login'))

            # Set session
            session['userid'] = user_id
            session['role'] = actual_role
            session['email'] = user['email']
            session['name'] = user.get('name', '')

            # ✅ Update login count using user_id (correct key)
            try:
                user_table.update_item(
                    Key={'user_id': user_id},
                    UpdateExpression='SET login_count = if_not_exists(login_count, :zero) + :inc',
                    ExpressionAttributeValues={':inc': 1, ':zero': 0}
                )
            except Exception as e:
                logging.error(f"Failed to update login count for {user_id}: {e}")

            flash("Login successful.", "success")
            return redirect(url_for(f"{actual_role}_dashboard"))
        else:
            flash("Invalid credentials.", "danger")
            logging.warning(f"Login failed for email: {email}")

    return render_template('login.html')


# ---------- Logout User ----------
@app.route('/logout')
def logout():
    user = session.get('email', 'Unknown')
    session.pop('userid', None)
    session.pop('role', None)
    session.pop('email', None)
    session.pop('name', None)
    flash('You have been logged out.', 'success')
    logging.info(f"User logged out: {user}")
    return redirect(url_for('login'))

# ---------- Patient Dashboard ----------
@app.route('/patient_dashboard')
@role_required('patient')
def patient_dashboard():
    user_id = session['userid']

    # ✅ Fetch logged-in patient from DynamoDB
    try:
        user_response = user_table.get_item(Key={'user_id': user_id})
        user = user_response.get('Item')
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('logout'))
    except Exception as e:
        logging.error(f"Failed to fetch user profile: {e}")
        flash("Error fetching user profile.", "danger")
        return redirect(url_for('logout'))

    email = user['email']

    # Get search query
    search_query = request.args.get('search', '').strip().lower()

    # ✅ Fetch appointments using GSI
    try:
        response = appointment_table.query(
            IndexName='PatientEmailIndex',
            KeyConditionExpression=boto3.dynamodb.conditions.Key('patient_email').eq(email)
        )
        appointments = response.get('Items', [])
    except Exception as e:
        logging.error(f"Failed to fetch appointments for patient {email}: {e}")
        appointments = []

    # ✅ Load all doctors from DynamoDB (to replace users.items())
    try:
        doctor_scan = user_table.scan(
            FilterExpression=Attr('role').eq('doctor')
        )
        doctor_list = {doc['user_id']: doc for doc in doctor_scan.get('Items', [])}
    except Exception as e:
        logging.error(f"Failed to fetch doctor list: {e}")
        doctor_list = {}

    # Apply search filter (based on doctor name or appointment status)
    if search_query:
        filtered_appointments = []
        for a in appointments:
            doctor_id = a.get('doctor_id')
            doctor_name = doctor_list.get(doctor_id, {}).get('name', '').lower()
            status = a.get('status', '').lower()
            if search_query in doctor_name or search_query in status:
                filtered_appointments.append(a)
        appointments = filtered_appointments

    # Stats
    pending = sum(1 for a in appointments if a.get('status') == 'Pending')
    completed = sum(1 for a in appointments if a.get('status') == 'Completed')
    total = len(appointments)

    return render_template(
        'patient_dashboard.html',
        user=user,
        appointments=appointments,
        pending=pending,
        completed=completed,
        total=total,
        doctor_list=doctor_list
    )


# ---------- Doctor Dashboard ----------
@app.route('/doctor_dashboard')
@role_required('doctor')
def doctor_dashboard():
    user_id = session['userid']

    # ✅ Fetch doctor info from DynamoDB
    try:
        user_response = user_table.get_item(Key={'user_id': user_id})
        user = user_response.get('Item')
        if not user:
            flash("Doctor profile not found.", "danger")
            return redirect(url_for('logout'))
    except Exception as e:
        logging.error(f"Failed to fetch doctor profile: {e}")
        flash("Error loading dashboard.", "danger")
        return redirect(url_for('logout'))

    email = user['email']
    search_query = request.args.get('search', '').strip().lower()

    # ✅ Fetch appointments for this doctor via GSI
    try:
        response = appointment_table.query(
            IndexName='DoctorEmailIndex',
            KeyConditionExpression=boto3.dynamodb.conditions.Key('doctor_email').eq(email)
        )
        appointments = response.get('Items', [])
    except Exception as e:
        logging.error(f"Failed to fetch appointments for doctor {email}: {e}")
        appointments = []

    # ✅ Load patient data into a dict {user_id: user}
    try:
        patient_scan = user_table.scan(
            FilterExpression=Attr('role').eq('patient')
        )
        patient_dict = {p['user_id']: p for p in patient_scan.get('Items', [])}
    except Exception as e:
        logging.error(f"Failed to fetch patient list: {e}")
        patient_dict = {}

    # Apply search filter on patient name
    if search_query:
        appointments = [
            a for a in appointments
            if search_query in patient_dict.get(a.get('patient_id'), {}).get('name', '').lower()
        ]

    # Stats
    pending = sum(1 for a in appointments if a.get('status') == 'Pending')
    completed = sum(1 for a in appointments if a.get('status') == 'Completed')
    total = len(appointments)

    return render_template(
        'doctor_dashboard.html',
        user=user,
        appointments=appointments,
        pending=pending,
        completed=completed,
        total=total,
        users=patient_dict  # previously used for name resolution
    )


# ---------- Book Appointment ----------
@app.route('/book_appointment', methods=['GET', 'POST'])
@role_required('patient')
def book_appointment():
    if request.method == 'POST':
        appointment_id = str(uuid.uuid4())[:8]
        patient_id = session['userid']
        doctor_id = request.form['doctor_id']
        appointment_date = request.form['appointment_date']
        appointment_time = request.form['appointment_time']
        symptoms = request.form['symptoms']
        status = 'Pending'
        created_at = datetime.now().isoformat()

        # ✅ Fetch patient info
        try:
            patient_response = user_table.get_item(Key={'user_id': patient_id})
            patient = patient_response.get('Item', {})
        except Exception as e:
            logging.error(f"Failed to fetch patient data: {e}")
            flash("Could not retrieve your profile. Please try again.", "danger")
            return redirect(url_for('book_appointment'))

        # ✅ Fetch doctor info
        try:
            doctor_response = user_table.get_item(Key={'user_id': doctor_id})
            doctor = doctor_response.get('Item', {})
        except Exception as e:
            logging.error(f"Failed to fetch doctor data: {e}")
            flash("Could not retrieve doctor information.", "danger")
            return redirect(url_for('book_appointment'))

        patient_name = patient.get('name', 'Patient')
        patient_email = patient.get('email')
        doctor_name = doctor.get('name', 'Doctor')
        doctor_email = doctor.get('email')

        appointment_item = {
            'appointment_id': appointment_id,
            'patient_id': patient_id,
            'doctor_id': doctor_id,
            'date': appointment_date,
            'time': appointment_time,
            'symptoms': symptoms,
            'status': status,
            'created_at': created_at,
            'patient_name': patient_name,
            'doctor_name': doctor_name,
            'patient_email': patient_email,
            'doctor_email': doctor_email
        }

        try:
            appointment_table.put_item(Item=appointment_item)

            # ✅ Save notification for doctor
            notification_table.put_item(Item={
                'id': str(uuid.uuid4()),
                'user_id': doctor_id,
                'message': f"New appointment booked by {patient_name}",
                'timestamp': created_at
            })

            # ✅ Send emails
            send_email(
                patient_email,
                "Appointment Confirmation",
                f"<h3>Appointment Booked</h3><p>Date: {appointment_date}<br>Time: {appointment_time}</p>"
            )

            send_email(
                doctor_email,
                "New Appointment Alert",
                f"<h3>New Appointment</h3><p>Patient: {patient_name}<br>Date: {appointment_date}<br>Time: {appointment_time}<br>Symptoms: {symptoms}</p>"
            )

            logging.info(f"Appointment booked: {appointment_item}")
            flash("Appointment booked successfully.", "success")
            return redirect(url_for('patient_dashboard'))

        except Exception as e:
            logging.error(f"Failed to book appointment: {e}")
            flash("An error occurred while booking the appointment.", "danger")
            return redirect(url_for('book_appointment'))

    # ✅ Fetch list of doctors from DynamoDB
    try:
        doctor_scan = user_table.scan(FilterExpression=Attr('role').eq('doctor'))
        doctors = {d['user_id']: d for d in doctor_scan.get('Items', [])}
    except Exception as e:
        logging.error(f"Failed to load doctors for booking: {e}")
        flash("Unable to load doctors list.", "danger")
        doctors = {}

    return render_template('book_appointment.html', doctors=doctors)



# ---------- View Appointment ----------
@app.route('/appointment/<appointment_id>', methods=['GET', 'POST'])
@role_required('doctor')
def view_appointment_doctor(appointment_id):
    try:
        # ✅ Fetch appointment from DynamoDB
        response = appointment_table.get_item(Key={'appointment_id': appointment_id})
        appointment = response.get('Item')

        if not appointment or appointment['doctor_id'] != session['userid']:
            flash("Unauthorized or invalid appointment.", "danger")
            return redirect(url_for('doctor_dashboard'))

        # ✅ If doctor submits diagnosis
        if request.method == 'POST':
            diagnosis = request.form['diagnosis']
            treatment_plan = request.form['treatment_plan']
            prescription = request.form['prescription']
            updated_at = datetime.now().isoformat()

            # ✅ Update appointment
            appointment_table.update_item(
                Key={'appointment_id': appointment_id},
                UpdateExpression="SET diagnosis=:d, treatment_plan=:t, prescription=:p, #s=:s, updated_at=:u",
                ExpressionAttributeNames={'#s': 'status'},
                ExpressionAttributeValues={
                    ':d': diagnosis,
                    ':t': treatment_plan,
                    ':p': prescription,
                    ':s': 'Completed',
                    ':u': updated_at
                }
            )

            # ✅ Fetch patient & doctor info from DB
            try:
                patient_resp = user_table.get_item(Key={'user_id': appointment['patient_id']})
                patient = patient_resp.get('Item', {})
                patient_email = patient.get('email')
            except Exception as e:
                logging.warning(f"Failed to fetch patient for email: {e}")
                patient_email = None

            try:
                doctor_resp = user_table.get_item(Key={'user_id': session['userid']})
                doctor = doctor_resp.get('Item', {})
                doctor_name = doctor.get('name', 'Doctor')
            except Exception as e:
                logging.warning(f"Failed to fetch doctor name: {e}")
                doctor_name = "Doctor"

            # ✅ Send email to patient
            if ENABLE_EMAIL and patient_email:
                email_body = (
                    f"<h3>Appointment Completed</h3>"
                    f"<p><strong>Doctor:</strong> {doctor_name}</p>"
                    f"<p><strong>Diagnosis:</strong> {diagnosis}</p>"
                    f"<p><strong>Treatment Plan:</strong> {treatment_plan}</p>"
                    f"<p><strong>Prescription:</strong> {prescription}</p>"
                )
                send_email(patient_email, "Your Diagnosis Report", email_body)

            flash("Diagnosis submitted successfully.", "success")
            return redirect(url_for('doctor_dashboard'))

        # ✅ Fetch patient for viewing (non-edit mode)
        try:
            patient_resp = user_table.get_item(Key={'user_id': appointment['patient_id']})
            patient = patient_resp.get('Item', {})
        except Exception as e:
            logging.error(f"Failed to fetch patient data for viewing: {e}")
            patient = {}

        return render_template(
            'view_appointment_doctor.html',
            appointment=appointment,
            patient=patient
        )

    except Exception as e:
        logging.error(f"Failed to load appointment: {e}")
        flash("Error loading appointment.", "danger")
        return redirect(url_for('doctor_dashboard'))



@app.route('/submit_diagnosis/<appointment_id>', methods=['POST'])
@role_required('doctor')
def submit_diagnosis(appointment_id):
    doctor_id = session['userid']

    try:
        # ✅ Fetch appointment from DynamoDB
        response = appointment_table.get_item(Key={'appointment_id': appointment_id})
        appointment = response.get('Item')

        if not appointment or appointment['doctor_id'] != doctor_id:
            flash("Unauthorized or invalid appointment.", "danger")
            return redirect(url_for('doctor_dashboard'))

        # ✅ Update appointment with submitted data
        appointment_table.update_item(
            Key={'appointment_id': appointment_id},
            UpdateExpression="SET diagnosis=:d, treatment_plan=:tp, prescription=:pr, #s=:s, updated_at=:u",
            ExpressionAttributeNames={'#s': 'status'},
            ExpressionAttributeValues={
                ':d': request.form['diagnosis'],
                ':tp': request.form['treatment_plan'],
                ':pr': request.form['prescription'],
                ':s': 'Completed',
                ':u': datetime.now().isoformat()
            }
        )

        flash("Diagnosis submitted successfully!", "success")
        logging.info(f"Diagnosis updated for appointment: {appointment_id}")
        return redirect(url_for('doctor_dashboard'))

    except Exception as e:
        logging.error(f"Failed to submit diagnosis for appointment {appointment_id}: {e}")
        flash("An error occurred while submitting the diagnosis.", "danger")
        return redirect(url_for('doctor_dashboard'))


@app.route('/appointment_patient/<appointment_id>')
@role_required('patient')
def view_appointment_patient(appointment_id):
    patient_id = session['userid']

    try:
        # ✅ Fetch appointment from DynamoDB
        response = appointment_table.get_item(Key={'appointment_id': appointment_id})
        appointment = response.get('Item')

        if not appointment or appointment['patient_id'] != patient_id:
            flash("Unauthorized or invalid appointment.", "danger")
            return redirect(url_for('patient_dashboard'))

        # ✅ Ensure created_at exists
        if 'created_at' not in appointment:
            appointment['created_at'] = datetime.now().isoformat()

        # ✅ Fetch doctor info from DynamoDB
        try:
            doctor_resp = user_table.get_item(Key={'user_id': appointment['doctor_id']})
            doctor = doctor_resp.get('Item', {})
        except Exception as e:
            logging.error(f"Failed to fetch doctor info for appointment {appointment_id}: {e}")
            doctor = {}

        return render_template(
            'view_appointment_patient.html',
            appointment=appointment,
            doctor=doctor
        )

    except Exception as e:
        logging.error(f"Error loading patient appointment view: {e}")
        flash("Could not load the appointment.", "danger")
        return redirect(url_for('patient_dashboard'))


# ---------- Doctor Profile ----------
@app.route('/doctor/profile', methods=['GET', 'POST'])
@role_required('doctor')
def doctor_profile():
    user_id = session['userid']
    try:
        # ✅ Fetch doctor info from DynamoDB
        response = user_table.get_item(Key={'user_id': user_id})
        user = response.get('Item', {})

        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            age = request.form.get('age', '').strip()
            gender = request.form.get('gender', '').strip()
            specialization = request.form.get('specialization', '').strip()

            update_expression = (
                "SET #name = :name, age = :age, gender = :gender, specialization = :spec"
            )
            expression_values = {
                ':name': name,
                ':age': age,
                ':gender': gender,
                ':spec': specialization
            }

            user_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ExpressionAttributeNames={'#name': 'name'}
            )

            session['name'] = name  # ✅ Keep updated for navbar
            flash("Profile updated successfully.", "success")
            return redirect(url_for('doctor_profile'))

        return render_template('doctor_profile.html', user=user)

    except Exception as e:
        logging.error(f"Doctor profile error: {e}")
        flash("Failed to load doctor profile.", "danger")
        return redirect(url_for('doctor_dashboard'))


# ---------- Patient Profile ----------
@app.route('/patient/profile', methods=['GET', 'POST'])
@role_required('patient')
def patient_profile():
    user_id = session['userid']
    try:
        response = user_table.get_item(Key={'user_id': user_id})
        user = response.get('Item', {})

        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            age = request.form.get('age', '').strip()
            gender = request.form.get('gender', '').strip()

            update_expression = "SET #name = :name, age = :age, gender = :gender"
            expression_values = {
                ':name': name,
                ':age': age,
                ':gender': gender
            }

            user_table.update_item(
                Key={'user_id': user_id},
                UpdateExpression=update_expression,
                ExpressionAttributeValues=expression_values,
                ExpressionAttributeNames={'#name': 'name'}
            )

            session['name'] = name
            flash("Profile updated successfully.", "success")
            return redirect(url_for('patient_profile'))

        return render_template('patient_profile.html', user=user)

    except Exception as e:
        logging.error(f"Patient profile error: {e}")
        flash("Failed to load patient profile.", "danger")
        return redirect(url_for('patient_dashboard'))

@app.route('/view_diagnosis')
@role_required('patient')
def view_diagnosis():
    patient_email = session['email']
    diagnoses = []

    try:
        # ✅ Scan appointments with a diagnosis and matching patient email
        response = appointment_table.scan(
            FilterExpression=Attr('patient_email').eq(patient_email) & Attr('diagnosis').exists()
        )
        diagnoses = response.get('Items', [])
    except Exception as e:
        logging.error(f"Failed to fetch diagnosis records for {patient_email}: {e}")
        flash("Could not retrieve diagnosis information.", "danger")

    return render_template('view_diagnosis.html', diagnoses=diagnoses)


@app.route('/health')
def health():
    return jsonify({'status': 'healthy'}), 200


# ---------- Error Handlers ----------

@app.errorhandler(404)
def page_not_found(error):
    logging.warning(f"404 Not Found: {request.path}")
    try:
        return render_template('404.html'), 404
    except Exception as e:
        logging.error(f"Failed to render 404 page: {e}")
        return jsonify({'error': 'Page not found'}), 404

@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"500 Internal Server Error: {error}")
    try:
        return render_template('500.html'), 500
    except Exception as e:
        logging.critical(f"Failed to render 500 page: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ---------- Notifications ----------
@app.route('/notifications')
def view_notifications():
    if not is_logged_in():
        flash('Please log in to view notifications.', 'danger')
        return redirect(url_for('login'))

    try:
        email = session['email']

        # ✅ Fetch notifications where user_email matches
        response = notification_table.scan(
            FilterExpression=Attr('user_email').eq(email)
        )
        user_notifications = response.get('Items', [])

        return render_template('notifications.html', notifications=user_notifications)

    except Exception as e:
        logging.error(f"Failed to fetch notifications for {email}: {e}")
        flash("Could not load notifications.", "danger")

        # ✅ Redirect based on role
        role = session.get('role')
        if role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
        elif role == 'patient':
            return redirect(url_for('patient_dashboard'))
        else:
            return redirect(url_for('login'))

# ---------- Run ----------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.environ.get('FLASK_ENV', '').lower() == 'development'
    logging.info(f"Starting Flask app on port {port} (debug={debug_mode})")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)
