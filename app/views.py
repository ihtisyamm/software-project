from flask import Flask, render_template, flash, request, redirect, url_for, session, jsonify, send_file
from flask_login import current_user, login_required

from app import app
from .forms import UserForm, LoginForm, UploadGPSForm, addFriendForm
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta, date

import os
import json 
import datetime as dt

import gpxpy
import gpxpy.gpx
from calendar import month_name

from .functions import is_logged_in, is_subscribed, get_stripe_info
from dotenv import load_dotenv
from supabase import create_client, Client
import stripe

url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(url, key)

@app.route('/')
def index():
    user = supabase.auth.get_user()

    if (user != None) and (is_subscribed() == True):
        return render_template("user_index.html")

    return render_template("index.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = UserForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        username = form.username.data
        try:
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {"data": {"username": username}}
            })
            user_data = {
                "email": email,
                "username": username,
                "is_admin": False
            }
            insert_response = supabase.table("user").insert(user_data).execute()
            return redirect(url_for('login'))
        except Exception as e:
            flash(str(e), 'signup_error')
            return render_template('user/signup.html', form=form)
    else:
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages:
                flash(f"Error in {fieldName}: {err}")

    return render_template('user/signup.html', title="RouteRush", form=form, category="signup_error")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        try:
            auth_response = supabase.auth.sign_in_with_password({"email": email, "password": password})

            user_response = supabase.table("user").select("*").eq("email", email).execute()
            user_data = user_response.data
            if user_data[0]['is_admin'] == True:
                return redirect(url_for('viewUser'))

            return redirect(url_for('dashboard'))

        except Exception as e:
            flash(str(e), 'login_error')
            return render_template('user/login.html', form=form)
    else:
        for fieldName, errorMessages in form.errors.items():
            for err in errorMessages:
                flash(f"Error in {fieldName}: {err}", 'login_error')

    return render_template('user/login.html', title="RouteRush", form=form, category='login_error')

@app.route('/logout')
def logout():
    supabase.auth.sign_out()
    return redirect(url_for('login'))

@app.route('/user/dashboard')
def dashboard():
    user = is_logged_in()
    subscription = [is_subscribed(), None, None]
    subscription[0] = is_subscribed()
    
    if user is None:
        return redirect(url_for('login'))

    if subscription[0] is False:
        return redirect(url_for('pricing'))

    str_info = get_stripe_info()
    subscription[1] = str_info["sub_type"]
    subscription[2] = str_info["end_date"]
    # Retrieve coordinate data from the database
    data, _ = supabase.table('uploaded-file').select("*").eq('user_id', user.user.id).execute()

    coordinates = []
    curr_file = [None, None, None] # curr_file contains [fileid, filename, coordinates] (ungku)
    for item in data[1]:
        curr_file[0] = item['file_id']
        curr_file[1] = item['filename']
        curr_file[2] = item['pointsdata']
        coordinates.append(curr_file)
        curr_file = [None, None, None]

    return render_template("user/dashboard.html", user=user, coordinates=coordinates, subscription=subscription)

@app.route('/upload', methods=['GET','POST'])
def upload():
    user = is_logged_in()

    if user is None:
        return redirect(url_for('login'))

    form = UploadGPSForm()

    return render_template("user/upload.html", form=form, user=user)

@app.route('/view/<id>')
def view(id):
    user = is_logged_in()

    if user is None:
        return redirect(url_for('login'))

    if is_subscribed() is False:
        return redirect(url_for('pricing'))

    data, count = supabase.table('uploaded-file').select("*").eq('file_id', id).execute()
    curr_file = data[1][0]

    other_data, count = supabase.table('uploaded-file').select("*").eq('user_id', user.user.id).neq('file_id', id).execute()
    files = other_data[1]

    return render_template("user/view.html", curr_file=curr_file, files=files)

@app.route('/delete/<id>')
def delete(id):
    # check if user has logged in
    user = supabase.auth.get_user()

    if user is None:
        return redirect(url_for('login'))

    # extract filename and user_id
    data, count = supabase.table('uploaded-file').select('filename', 'user_id').eq('id', id).execute()
    # if no row returned by query
    if count == 0:
        return "File not found"
    # if row found
    filename = data[1][0]['filename']
    user_id = data[1][0]['user_id']

    supabase.table('uploaded-file').delete().eq('id', id).execute()
    supabase.storage.from_('gpxfiles').remove(f"{user_id}/{filename}")

    return redirect(url_for('/user/upload'))

@app.route('/download/<id>')
def download(id):
    user = is_logged_in()

    if user is None:
        return redirect(url_for('login'))

    # Extract filename and user_id
    data, count = supabase.table('uploaded-file').select('filename', 'user_id').eq('file_id', id).execute()

    # If no row found
    if count == 0:
        return "File not found"

    # If row(s) found, loop through each file and generate a download link
    for row in data[1]:
        filename = row['filename']
        user_id = row['user_id']

        # Download file from storage
        response = supabase.storage.from_('gpxfiles').create_signed_url(f"{user_id}/{filename}", 5000)

        # Extract the signed URL from the response
        signed_url = response['signedURL']

        # Redirect the user to the signed URL for direct download
        return redirect(signed_url)

@app.route('/api/upload', methods=['POST'])
def file_upload():
    # check if user has logged in
    user = supabase.auth.get_user()

    if user is None:
        return redirect(url_for('login'))

    # check if the post request contains a file
    if 'file' not in request.files:
        return 'No file part'

    file = request.files['file']

    # if user does not select a file, the browser submits
    # an empty file without a filename
    if file.filename == '':
        return 'No selected file'

    new_file = secure_filename(file.filename)
    file.save(new_file)

    with open(new_file, "r") as gpx_file:
        gpx = gpxpy.parse(gpx_file)

    points = []

    for track in gpx.tracks:
        for segment in track.segments:
            for point in segment.points:
                points.append([point.latitude, point.longitude])

    if len(points) == 0:
        for point in gpx.waypoints:
            points.append([point.latitude, point.longitude])

    if len(points) == 0:
        for route in gpx.routes:
            for point in route.points:
                points.append([point.latitude, point.longitude])

    with open(new_file, "rb") as f:
        supabase.storage.from_('gpxfiles').upload(f"/{user.user.id}/{new_file}", f, {"content-type": "application/gpx+xml"})

    # after uploading, close the file
    f.close()

    data, count = supabase.table('uploaded-file').insert({"filename":new_file, "pointsdata":points}).execute()

    os.remove(new_file)

    return redirect(url_for('dashboard'))


@app.route('/add_friend', methods=['GET', 'POST'])
def add_friend():
    user = is_logged_in()
    if user is None:
        return redirect(url_for('login'))

    form = addFriendForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            if username:
                # Fetch user details by username from Supabase
                user_response = supabase.table("user").select("*").eq("username", username).execute()
                user_data = user_response.data
                if user_data:
                    friend = user_data[0]
                    # Check if they are already friends or if a request is pending
                    result = supabase.table("friendship").select("*").eq("user_id", user.user.id).\
                        eq("friend_id", friend['id']).execute()
                    if not result.data:
                        # Create two-way friend requests
                        friend_request1 = {
                            "username": user.user.user_metadata['username'],
                            "user_id": user.user.id,
                            "friend_username": username,
                            "friend_id": user_data[0]['id'],
                            "status": "Accepted"
                        }
                        friend_request2 = {
                            "username": username,
                            "user_id": user_data[0]['id'],
                            "friend_username": user.user.user_metadata['username'],
                            "friend_id": user.user.id,
                            "status": "Accepted"
                        }

                        # Insert friend requests into Supabase
                        supabase.table("friendship").insert(friend_request1).execute()
                        supabase.table("friendship").insert(friend_request2).execute()

                        flash(f'You are now friends with {username}!', 'friend_error')
                    else:
                        flash("Already friend", 'friend_error')
                else:
                    flash('User not found.', 'friend_error')
            else:
                flash('Please enter a username.', 'friend_error')
        else:
            for fieldName, errorMessages in form.errors.items():
                for err in errorMessages:
                    flash(f"Error in {fieldName}: {err}", 'friend_error')

    response = supabase.table("friendship").select("*").eq("username", user.user.user_metadata['username']).execute()

    friend_usernames = {item['friend_username'] for item in response.data}
    if friend_usernames:
        details_response = supabase.table('user').select('*').in_('username', list(friend_usernames)).execute()
        friends = details_response.data
    else:
        friends = []

    return render_template('user/friends.html', form=form, friends=friends, category='friend_error')


@app.route('/pricing')
def pricing():
    user = supabase.auth.get_user()
    sub_info = None

    if is_subscribed():
        sub_info = get_stripe_info()

    if user != None:
        return render_template("payment/user_pricing.html", sub_info=sub_info)

    return render_template("payment/pricing.html")


@app.route('/config')
def get_key():
    stripe_public_key = os.getenv("STRIPE_PUB_KEY")
    stripe_config = {'publicKey': stripe_public_key}

    return jsonify(stripe_config)


@app.route('/create-checkout-session/<price_id>')
def checkout_session(price_id):
    user = supabase.auth.get_user()

    if user == None:
        return redirect(url_for('login'))

    domain_url = "http://localhost:5000/"
    stripe.api_key = os.getenv("STRIPE_SEC_KEY")

    data, count = supabase.table('stripe-user').select('stripeid').eq('userid', user.user.id).execute()

    if len(data[1]) == 0:
        customer_id = None
    else:
        customer_id = data[1][0]['stripeid']

    try:
        checkout_session = stripe.checkout.Session.create(
            customer=customer_id,
            success_url=domain_url+ "success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=domain_url,
            client_reference_id=user.user.id,
            payment_method_types=["card"],
            mode="subscription",
            line_items=[
                {
                    "price": price_id,
                    "quantity": 1
                }
            ]
        )
        return jsonify({"sessionId":checkout_session["id"]})
    except Exception as e:
        return jsonify(error=str(e)), 403

@app.route('/success')
def success():
    stripe.api_key = os.getenv("STRIPE_SEC_KEY")
    user = supabase.auth.get_user()

    if user == None:
        return redirect(url_for('login'))

    stripe_res = stripe.Customer.list(email=user.user.email)
    data, count = supabase.table('stripe-user').select('stripeid').eq('userid', user.user.id).execute()

    if len(data[1]) == 0:
        stripe_res = stripe.Customer.list(email=user.user.email)
        to_add = stripe_res['data'][0]['id']
        supabase.table('stripe-user').insert({'stripeid':to_add}).execute()

    return redirect(url_for("dashboard"))

@app.route('/user/confirmation')
def confirmation():
    user = supabase.auth.get_user()

    if user == None:
        return redirect(url_for('login'))
    
    return render_template("user/confirmation.html")

@app.route('/user/cancel')
def cancel():
    stripe.api_key = os.getenv("STRIPE_SEC_KEY")
    user = supabase.auth.get_user()

    if user == None:
        return redirect(url_for('login'))

    response = supabase.table('stripe-user').select('stripeid').eq('userid', user.user.id).execute()
    
    # Check if the query was successful and if there are any results
    if response.data:
        customer_id = response.data[0]['stripeid']
    # Set Stripe API key
    #stripe.api_key = os.getenv("STRIPE_SEC_KEY")

    # Retrieve user's subscriptions from Stripe
    subscriptions = stripe.Subscription.list(customer=customer_id)

    if subscriptions:
        cancelled_id = []
        # Cancel each subscription
        for subscription in subscriptions:
            stripe.Subscription.delete(subscription.id)
            cancelled_id.append(subscription.id)

    return render_template("user/cancel.html", user=user)
  
@app.context_processor
def inject_form():
    return {'form': addFriendForm()}  # This makes `form` available in all templates

@app.route('/user/changesub/<sub_type>')
def change_sub(sub_type):
    user = supabase.auth.get_user()
    db_res, res = supabase.table('stripe-user').select('stripeid').eq('userid', user.user.id).execute()

    if len(db_res[1]) != 0:
        stripe.api_key = os.getenv("STRIPE_SEC_KEY")
        stripe_id = db_res[1][0]['stripeid']
        stripe_res = stripe.Subscription.list(customer=stripe_id)

    sub_id = stripe_res['data'][0]['id']
    sub_item_id = stripe_res['data'][0]['items']['data'][0]['id']

    stripe.Subscription.modify(sub_id, items=[{"id":sub_item_id, "price":sub_type}])

    return redirect(url_for('dashboard'))

@app.route('/owner/view_revenue')
def viewUser():
    stripe.api_key = os.getenv("STRIPE_SEC_KEY")

    params = {
        'limit': 10000,
    }

    customers = stripe.Customer.list(**params)
    subscriptions = stripe.Subscription.list(status='active')['data']

    start_of_year = datetime(date.today().year, 1, 1)
    revenue_data = {}
    monthly_revenue = {i: 0 for i in range(1, 13)}
    yearly_revenue = 0
    total_users = len(customers)
    subscribed_users = len(subscriptions)

    for subscription in subscriptions:
        subscription_items = stripe.SubscriptionItem.list(subscription=subscription.id)['data']

        for item in subscription_items:
            price = item.price.unit_amount
            quantity = item.quantity

            revenue = (price * quantity) / 100
            start_date = datetime.fromtimestamp(subscription.start_date)
            period_end = datetime.fromtimestamp(subscription.current_period_end)

            current_date = start_date
            while current_date <= period_end:
                week_number = (current_date - start_of_year).days // 7 + 1
                week_start = start_of_year + timedelta(weeks=week_number - 1)

                if week_start not in revenue_data:
                    revenue_data[week_start] = 0
                revenue_data[week_start] += revenue

                monthly_revenue[current_date.month] += revenue
                yearly_revenue += revenue

                current_date += timedelta(days=7)

    sorted_revenue_data = sorted(revenue_data.items())

    months = list(month_name)[1:] 
    current_year = date.today().year

    subscriptions_g = stripe.Subscription.list(status='active')['data']

    start_of_year = datetime(date.today().year, 1, 1) 
    future_revenue = {}

    for subscription in subscriptions_g:
        subscription_items = stripe.SubscriptionItem.list(subscription=subscription.id)['data']

        for item in subscription_items:
            price = item.price.unit_amount
            quantity = item.quantity

            revenue = (price * quantity) / 100

            start_date = datetime.fromtimestamp(subscription.start_date)
            period_end = datetime.fromtimestamp(subscription.current_period_end)

            current_date = start_date
            while current_date <= period_end:
                week_number = (current_date - start_of_year).days // 7 + 1
                week_start = start_of_year + timedelta(weeks=week_number - 1)

                if week_start not in future_revenue:
                    future_revenue[week_start] = 0
                future_revenue[week_start] += revenue

                current_date += timedelta(days=7)

    sorted_future_revenue = sorted(future_revenue.items())

    labels = list(range(1, 53))
    values = [future_revenue.get(start_of_year + timedelta(weeks=week - 1), 0) for week in labels]

    labels_json = json.dumps(labels)
    values_json = json.dumps(values)

    return render_template('owner/ownerview_user.html', revenue_data=revenue_data, monthly_revenue=monthly_revenue, yearly_revenue=yearly_revenue, total_users=total_users, subscribed_users=subscribed_users, months=months, current_year=current_year, labels=labels_json, values=values_json)

@app.route('/view/friends')
def view_friends():
    user = is_logged_in()

    if user is None:
        return redirect(url_for('login'))
    
    friends_response = supabase.table("friendship").select("friend_username, friend_id").eq("username", user.user.user_metadata['username']).execute()
    friends = friends_response.data

    friend_profiles = []
    for friend in friends:
        friend_details_response = supabase.table("user").select("username").eq("id", friend['friend_id']).execute()
        friend_details = friend_details_response.data[0]
        friend_profiles.append(friend_details)

        return render_template('user/view_friends.html', friends=friend_profiles)

@app.route('/user/<username>')
def friend_dashboard(username):
    user = is_logged_in()
    
    if user is None:
        return(url_for('login'))
    
    user_response = supabase.table("user").select("*").eq("username", username).execute()
    user_data = user_response.data

    if not user_data:
        return "User not found"
    
    friend = user_data[0]

    files_response = supabase.table("uploaded-file").select("*").eq("user_id", friend['id']).execute()
    files = files_response.data

    return render_template('user/friend_dashboard.html', friend=friend, files=files)
