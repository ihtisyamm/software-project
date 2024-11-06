import os
import datetime as dt
import stripe

from supabase import create_client, Client

url: str = os.getenv("SUPABASE_URL")
key: str = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(url, key)

# check if user is logged in
def is_logged_in():
    user = supabase.auth.get_user()
    if user != None:
        return user
    return None

# check if user is subscribed
def is_subscribed():
    stripe.api_key = os.getenv("STRIPE_SEC_KEY")
    user = is_logged_in()

    if user == None:
        return False

    db_res, res = supabase.table('stripe-user').select('stripeid').eq('userid', user.user.id).execute()

        # check if user has relation with stripe cust object (ungku)
    if len(db_res[1]) != 0:
        stripe_id = db_res[1][0]['stripeid']
        stripe_res = stripe.Subscription.list(customer=stripe_id)

        # check if user is in subscription list (ungku)
        if len(stripe_res['data']) == 1:
            return True

    return False

def get_stripe_info():
    stripe.api_key = os.getenv("STRIPE_SEC_KEY")
    user = is_logged_in()

    if user == None:
        return False
    
    if is_subscribed():
         db_res, res = supabase.table('stripe-user').select('stripeid').eq('userid', user.user.id).execute()
         
         if len(db_res[1]) != 0:
            stripe.api_key = os.getenv("STRIPE_SEC_KEY")
            stripe_id = db_res[1][0]['stripeid']
            stripe_res = stripe.Subscription.list(customer=stripe_id)

            time_e = stripe_res['data'][0]['current_period_end']
            frmt_time = dt.datetime.fromtimestamp(time_e).strftime('%d/%m/%Y')

            if stripe_res['data'][0]['plan']['product'] == "prod_PfLKHi9D2EoGa2":
                sub_type = "Weekly"
            elif stripe_res['data'][0]['plan']['product'] == "prod_PfLLT6pqmZ0Tb6":
                sub_type = "Monthly"
            else:
                sub_type = "Yearly"

    return {"sub_type": sub_type, "end_date": frmt_time}