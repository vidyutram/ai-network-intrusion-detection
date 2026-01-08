import numpy as np
import pandas as pd
import joblib

from data import FEATURE_NAMES

_AE_BUNDLE = None

def _load_bundle():
    global _AE_BUNDLE
    if _AE_BUNDLE is None:
        try:
            _AE_BUNDLE = joblib.load("ae_model.joblib")
            print("[INFO] Autoencoder model loaded from ae_model.joblib")
        except Exception as e:
            print("[WARN] Could not load ae_model.joblib (autoencoder disabled):", e)
            _AE_BUNDLE = None
    return _AE_BUNDLE


def has_autoencoder() -> bool:
    return _load_bundle() is not None


def anomaly_score(feature_dict: dict) -> float | None:
    """
    Returns a reconstruction error (MSE) as anomaly score.
    Higher = more anomalous.
    Returns None if no autoencoder is available.
    """
    bundle = _load_bundle()
    if bundle is None:
        return None

    preprocessor = bundle["preprocessor"]
    regressor = bundle["regressor"]

    df = pd.DataFrame([feature_dict])[FEATURE_NAMES]
    try:
        X_enc = preprocessor.transform(df)
        recon = regressor.predict(X_enc)
        err = np.mean((X_enc - recon) ** 2)
        return float(err)
    except Exception as e:
        print("[WARN] Failed to compute anomaly score:", e)
        return None
