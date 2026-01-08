from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

from data import maybe_download, load_data, prepare_labels, FEATURE_NAMES
from model import build_pipeline, save_model


def main():
    print("=== TRAINING NETWORK INTRUSION DETECTION MODEL ===")

    maybe_download()
    train_df, test_df = load_data()

    train_df = prepare_labels(train_df)
    test_df = prepare_labels(test_df)

    X_train = train_df[FEATURE_NAMES]
    y_train = train_df["binary_label"]
    X_test = test_df[FEATURE_NAMES]
    y_test = test_df["binary_label"]

    model = build_pipeline()

    print("[INFO] Training model...")
    model.fit(X_train, y_train)

    print("[INFO] Evaluating on test data...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print("\n=== CLASSIFICATION REPORT ===")
    print(classification_report(y_test, y_pred, digits=4))

    print("=== CONFUSION MATRIX ===")
    print(confusion_matrix(y_test, y_pred))

    print("=== ROC AUC ===")
    print(roc_auc_score(y_test, y_proba))

    save_model(model)


if __name__ == "__main__":
    main()
