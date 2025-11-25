from flask import Flask, render_template, request
import pickle
import numpy as np

app = Flask(__name__)

# Load model and scaler
# model = pickle.load(open("intrusion_model.pkl", "rb"))
# scaler = pickle.load(open("scaler.pkl", "rb"))

model = pickle.load(open("ann_model.pkl", "rb"))
scaler = pickle.load(open("scaler.pkl", "rb"))


# Dummy encoding used during training (MUST MATCH your original notebook)
protocol_map = {"tcp": 0, "udp": 1, "icmp": 2}
service_map = {"http": 0, "ftp": 1, "smtp": 2, "domain_u": 3, "other": 4}
flag_map = {"SF": 0, "S0": 1, "REJ": 2, "RSTR": 3, "OTH": 4}

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():

    try:
        duration = float(request.form["duration"])
        protocol_type = protocol_map[request.form["protocol_type"]]
        service = service_map[request.form["service"]]
        flag = flag_map[request.form["flag"]]
        src_bytes = float(request.form["src_bytes"])
        dst_bytes = float(request.form["dst_bytes"])
        wrong_fragment = float(request.form["wrong_fragment"])
        urgent = float(request.form["urgent"])

        # Arrange in exact order used during training
        features = [[
            duration, protocol_type, service, flag,
            src_bytes, dst_bytes, wrong_fragment, urgent
        ]]

        scaled_features = scaler.transform(features)
        prediction = model.predict(scaled_features)[0]

        if prediction == 0:
            result = "Normal Traffic"
        else:
            result = "Intrusion Detected! ⚠️"

        return f"<h1>{result}</h1>"

    except Exception as e:
        return f"Error: {str(e)}"


if __name__ == "__main__":
    app.run(debug=True)
