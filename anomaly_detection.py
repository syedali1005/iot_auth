import logging
import pandas as pd
from sklearn.ensemble import IsolationForest

model = None  # Global variable for the model

def train_model(collection):
    """Train the Isolation Forest model with authentication attempts data."""
    data = list(collection.find({}, {'_id': 0, 'success': 1, 'device_id': 1}))
    df = pd.DataFrame(data)

    # Log the size of the dataset
    logging.info(f"Training model with {len(df)} records.")

    if len(df) < 10:
        logging.warning("Not enough data to train the model.")
        return False

    # Convert non-numeric fields to numeric
    df['device_id'] = pd.factorize(df['device_id'])[0]

    X = df[['device_id', 'success']]
    
    global model
    model = IsolationForest(contamination=0.1)
    model.fit(X)
    logging.info("Model trained successfully.")
    return True

def monitor(new_attempt):
    global model

    if model is None:
        logging.warning("Model has not been trained.")
        return False

    # Log the new attempt
    logging.info(f"Monitoring new attempt: {new_attempt}")

    # Convert the new attempt to a DataFrame
    attempt_df = pd.DataFrame([{
        'device_id': new_attempt['device_id'],
        'success': 1 if new_attempt['success'] else 0
    }])
    
    attempt_df['device_id'] = pd.factorize(attempt_df['device_id'])[0]

    # Log the input features
    logging.info(f"Input features for prediction: {attempt_df.values}")

    prediction = model.predict(attempt_df)
    logging.info(f"Prediction for new attempt {new_attempt}: {prediction}")

    # Log the decision-making process
    if prediction[0] == -1:
        logging.warning("Anomaly detected.")
    else:
        logging.info("Normal activity.")

    return prediction[0] == -1  # Anomaly is indicated by -1
