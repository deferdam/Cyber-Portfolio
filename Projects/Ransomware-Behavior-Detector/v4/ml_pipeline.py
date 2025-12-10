import json
from datetime import datetime

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, classification_report

FEATURE_NAMES = [
    "risk_score",
    "max_burst_unique_files_in_window",
    "total_unique_files_touched",
    "unique_files_in_long_window",
    "directory_spread",
    "num_suspicious_extensions",
    "num_outbound_external_connections",
    "abnormal_location",
    "elevated_integrity",
    "num_risk_factors",
    "lifetime_seconds",
]

def load_detection_report(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def features_from_entry(entry):
    first_seen = datetime.fromisoformat(entry["first_seen"])
    last_seen = datetime.fromisoformat(entry["last_seen"])
    lifetime_seconds = (last_seen - first_seen).total_seconds()

    num_susp_ext = len(entry.get("suspicious_extensions", []))
    num_outbound = len(entry.get("outbound_external_connections", []))
    num_risk_factors = len(entry.get("risk_factors", []))

    return [
        float(entry.get("risk_score", 0.0)),
        int(entry.get("max_burst_unique_files_in_window", 0)),
        int(entry.get("total_unique_files_touched", 0)),
        int(entry.get("unique_files_in_long_window", 0)),
        int(entry.get("directory_spread", 0)),
        int(num_susp_ext),
        int(num_outbound),
        int(bool(entry.get("abnormal_location", False))),
        int(bool(entry.get("elevated_integrity", False))),
        int(num_risk_factors),
        float(lifetime_seconds),
    ]

def load_labels(labels_path):
    """
    labels_large.json :
    [
      { "process_name": "...", "pid": 1234, "label": 0 or 1 },
      ...
    ]
    """
    with open(labels_path, encoding="utf-8") as f:
        data = json.load(f)
    # key: (process_name, pid) -> label
    mapping = {}
    for item in data:
        key = (item["process_name"], int(item["pid"]))
        mapping[key] = int(item["label"])
    return mapping

def build_dataset_from_report(report_path, labels_path):
    report = load_detection_report(report_path)
    label_map = load_labels(labels_path)

    X = []
    y = []
    meta = []  # keep name of process / pid

    for entry in report.get("suspicious_processes", []):
        key = (entry["process_name"], int(entry["pid"]))
        if key not in label_map:
            # no label : ignore
            continue
        X.append(features_from_entry(entry))
        y.append(label_map[key])
        meta.append(key)

    return X, y, meta

def train_and_evaluate(report_paths, labels_path, model_out="ransomware_model.joblib"):
    """
    report_paths : liste de chemins de detection_report.json
    labels_path : labels_large.json
    """
    X_all = []
    y_all = []

    for rp in report_paths:
        X, y, _ = build_dataset_from_report(rp, labels_path)
        X_all.extend(X)
        y_all.extend(y)

    if not X_all:
        raise RuntimeError("Pas de données labellisées trouvées, impossible d'entraîner le modèle.")

    X_train, X_test, y_train, y_test = train_test_split(
        X_all, y_all, test_size=0.3, random_state=42, stratify=y_all
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced"
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    prec = precision_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)

    print("Precision:", prec)
    print("Recall:", rec)
    print("Classification report:\n", classification_report(y_test, y_pred, zero_division=0))

    joblib.dump(clf, model_out)
    print(f"Modèle sauvegardé dans {model_out}")

    return clf, prec, rec

def apply_model_on_report(report_path, model_path, ml_threshold=0.5):
    report = load_detection_report(report_path)
    clf = joblib.load(model_path)

    suspicious = report.get("suspicious_processes", [])
    if not suspicious:
        print("Aucun process dans suspicious_processes.")
        return report

    X = []
    meta = []
    for entry in suspicious:
        X.append(features_from_entry(entry))
        meta.append(entry)

    proba = clf.predict_proba(X)[:, 1]

    # Add infos ML in report
    for entry, p in zip(meta, proba):
        entry["ml_ransomware_probability"] = float(p)
        entry["ml_predicted_label"] = bool(p >= ml_threshold)

    # filter to find the most suspect
    suspicious_sorted = sorted(
        suspicious,
        key=lambda e: e.get("ml_ransomware_probability", 0.0),
        reverse=True
    )

    report["suspicious_processes"] = suspicious_sorted
    if suspicious_sorted:
        top = suspicious_sorted[0]
        report["top_candidate_ml"] = {
            "process_name": top["process_name"],
            "pid": top["pid"],
            "ml_ransomware_probability": top["ml_ransomware_probability"],
        }

    # save better report
    out_path = "detection_report_with_ml.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Report enrichi écrit dans {out_path}")

    return report
