import numpy as np
from sklearn.ensemble import IsolationForest

# Train model
model = IsolationForest(
    n_estimators=100,
    contamination=0.2,
    random_state=42
)

# Train with dummy baseline data
X_train = np.random.rand(50, 4)
model.fit(X_train)

def predict_intrusion(features):
    X = np.array(features).reshape(1, -1)
    prediction = model.predict(X)

    # Convert anomaly score into severity
    score = model.decision_function(X)[0]

    if prediction[0] == -1:
        # Strong anomaly → HIGH
        if score < -0.2:
            return "HIGH"
        else:
            return "MEDIUM"
    else:
        return "LOW"