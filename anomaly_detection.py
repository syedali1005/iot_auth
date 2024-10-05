import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError

# Initialize the IsolationForest model
model = IsolationForest()

def train_model(auth_attempts_collection):
    """
    Train the IsolationForest model with the data from the auth_attempts_collection.
    """
    # Fetch data from MongoDB
    data = list(auth_attempts_collection.find({}, {'_id': 0}))  # Exclude _id from results
    df = pd.DataFrame(data)

    # Check if there are enough records to train the model
    if len(df) < 5:  # Set a threshold to ensure there is sufficient data
        print("Not enough data to train the model.")
        return False  # Return False to indicate that the model wasn't trained

    # Ensure data types are correct
    df['success'] = df['success'].astype(int)
    df['device_id'] = pd.factorize(df['device_id'])[0]

    # Prepare the features for training
    X = df[['device_id', 'success']]

    # Train the model
    model.fit(X)
    print("Model trained successfully.")
    return True  # Return True to indicate successful training

def monitor(data):
    """
    Monitor a new authentication attempt and detect if it's an anomaly.
    """
    input_data = pd.DataFrame({
        'device_id': [data['device_id']],
        'success': [data['success']],
    })
    input_data['device_id'] = pd.factorize(input_data['device_id'])[0]

    # Check if the model is fitted
    try:
        # Use the model to predict if the input data is an anomaly
        prediction = model.predict(input_data)
        return prediction[0] == -1  # Return True if anomaly is detected
    except NotFittedError:
        print("The model is not fitted yet. Train the model first.")
        return None  # Return None to indicate that no prediction was made

