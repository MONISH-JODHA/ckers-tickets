# test_twilio.py
import os
from twilio.rest import Client
from dotenv import load_dotenv

load_dotenv() # If you use a .env file for this test script

account_sid = os.environ.get("TWILIO_ACCOUNT_SID_TICKET_CMS")
auth_token = os.environ.get("TWILIO_AUTH_TOKEN_TICKET_CMS")
twilio_phone = os.environ.get("TWILIO_PHONE_NUMBER_TICKET_CMS")
to_phone = os.environ.get("EMERGENCY_CALL_RECIPIENT_PHONE_NUMBER_TICKET_CMS")

print(f"SID: {account_sid}")
print(f"Token: {'*' * len(auth_token) if auth_token else 'Not Set'}") # Don't print the actual token
print(f"From: {twilio_phone}")
print(f"To: {to_phone}")

if not all([account_sid, auth_token, twilio_phone, to_phone]):
    print("Missing one or more Twilio configuration variables.")
else:
    try:
        client = Client(account_sid, auth_token)
        call = client.calls.create(
                                twiml='<Response><Say>Hello from Twilio test!</Say></Response>',
                                to=to_phone,
                                from_=twilio_phone
                            )
        print(f"Call initiated successfully! SID: {call.sid}")
    except Exception as e:
        print(f"Error making test call: {e}")

# Run with: python test_twilio.py