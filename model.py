import pandas as pd
import joblib
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier

from data import FEATURE_NAMES


def build_pipeline():
    categorical = ["protocol_type", "service", "flag"]
    numeric = [f for f in FEATURE_NAMES if f not in categorical]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical),
            ("num", StandardScaler(), numeric),
        ]
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42
    )

    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", clf)
    ])


def save_model(model, path="nids_model.joblib"):
    joblib.dump(model, path)
    print("[INFO] Model saved:", path)


def load_model(path="nids_model.joblib"):
    print("[INFO] Loading model from:", path)
    return joblib.load(path)


def predict_single(model, feature_dict):
    """
    feature_dict must contain all FEATURE_NAMES keys.
    """
    df = pd.DataFrame([feature_dict])[FEATURE_NAMES]
    pred = model.predict(df)[0]

    if hasattr(model, "predict_proba"):
        proba = float(model.predict_proba(df)[0, 1])
    else:
        proba = None

    label = "ATTACK" if pred == 1 else "NORMAL"
    return label, proba
