import os
import urllib.request
import pandas as pd

DATA_DIR = "data_nsl_kdd"
TRAIN_FILE = os.path.join(DATA_DIR, "KDDTrain+.txt")
TEST_FILE = os.path.join(DATA_DIR, "KDDTest+.txt")

NSL_BASE_URL = "https://archive.ics.uci.edu/ml/machine-learning-databases/00229/"
TRAIN_URL = NSL_BASE_URL + "KDDTrain+.txt"
TEST_URL = NSL_BASE_URL + "KDDTest+.txt"

FEATURE_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

ALL_COLUMNS = FEATURE_NAMES + ["label", "difficulty"]


def maybe_download():
    os.makedirs(DATA_DIR, exist_ok=True)

    def dl(path, url):
        if not os.path.exists(path):
            print(f"[INFO] Downloading {url}")
            try:
                urllib.request.urlretrieve(url, path)
                print(f"[INFO] Saved to {path}")
            except Exception as e:
                print("Download failed. Please download manually and place the files in", DATA_DIR)
                print(e)

    dl(TRAIN_FILE, TRAIN_URL)
    dl(TEST_FILE, TEST_URL)


def load_data():
    print("[INFO] Loading NSL-KDD dataset...")
    train_df = pd.read_csv(TRAIN_FILE, header=None, names=ALL_COLUMNS)
    test_df = pd.read_csv(TEST_FILE, header=None, names=ALL_COLUMNS)
    print("[INFO] Train shape:", train_df.shape)
    print("[INFO] Test shape :", test_df.shape)
    return train_df, test_df


def prepare_labels(df):
    df = df.copy()
    df["binary_label"] = (df["label"] != "normal").astype(int)
    return df