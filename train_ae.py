import numpy as np
import joblib

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.neural_network import MLPRegressor

from data import maybe_download, load_data, prepare_labels, FEATURE_NAMES


def main():
    print("=== TRAINING AUTOENCODER-STYLE ANOMALY DETECTOR ===")

    maybe_download()
    train_df, _ = load_data()
    train_df = prepare_labels(train_df)

    # Use only normal traffic for training the autoencoder
    normal_df = train_df[train_df["binary_label"] == 0]
    X_normal = normal_df[FEATURE_NAMES]

    print(f"[INFO] Normal samples used for AE training: {len(X_normal)}")

    categorical = ["protocol_type", "service", "flag"]
    numeric = [f for f in FEATURE_NAMES if f not in categorical]

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), categorical),
            ("num", StandardScaler(), numeric),
        ]
    )

    print("[INFO] Fitting preprocessor...")
    X_enc = preprocessor.fit_transform(X_normal)
    X_enc = X_enc.astype(np.float32)

    # Simple MLP autoencoder: X_enc -> X_enc
    print("[INFO] Training MLPRegressor autoencoder...")
    ae = MLPRegressor(
        hidden_layer_sizes=(64, 32, 64),
        activation="relu",
        solver="adam",
        max_iter=20,   # keep it light; increase if you want better fit
        random_state=42,
        verbose=True,
    )

    ae.fit(X_enc, X_enc)

    # Quick check of reconstruction error on a subset
    idx = np.random.choice(X_enc.shape[0], size=min(1000, X_enc.shape[0]), replace=False)
    X_sub = X_enc[idx]
    recon = ae.predict(X_sub)
    mse = np.mean((X_sub - recon) ** 2)
    print(f"[INFO] Sample reconstruction MSE on normal subset: {mse:.6f}")

    bundle = {
        "preprocessor": preprocessor,
        "regressor": ae,
    }

    joblib.dump(bundle, "ae_model.joblib")
    print("[INFO] Saved autoencoder bundle to ae_model.joblib")


if __name__ == "__main__":
    main()
