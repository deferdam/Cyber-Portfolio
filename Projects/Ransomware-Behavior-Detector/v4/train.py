from ml_pipeline import train_and_evaluate

train_and_evaluate(
    report_paths=["detection_report.json"],
    labels_path="labels_large.json",
    model_out="ransomware_model.joblib"
)
