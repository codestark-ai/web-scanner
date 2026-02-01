from flask import Flask, render_template, request
from loader import load_scanners
import os

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    target = ""

    if request.method == "POST":
        target = request.form.get("url")
        scanners = load_scanners()

        for scanner in scanners:
            result = scanner.scan(target)
            if result:
                results.append(result)

    return render_template("index.html", results=results, target=target)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
