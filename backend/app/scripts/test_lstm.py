from app.services.lstm_inference import predict_sequence_anomaly
from app.services.storage_utils import get_logs_from_es

logs = get_logs_from_es()

score = predict_sequence_anomaly(logs)

print("LSTM Score:", score)