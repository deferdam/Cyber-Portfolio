from ml_pipeline import apply_model_on_report

apply_model_on_report(
    report_path="detection_report.json",
    model_path="ransomware_model.joblib",
    ml_threshold=0.5
)
