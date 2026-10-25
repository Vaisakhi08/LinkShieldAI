
async function checkURL() {
    const urlInput = document.getElementById("urlInput");
    const resultDiv = document.getElementById("result");

    const url = urlInput.value.trim();

    if (url === "") {
        resultDiv.className = "warning";
        resultDiv.textContent = "Please enter a URL to scan.";
        resultDiv.style.display = "block";
        return;
    }

    // Show the result box while scanning
    resultDiv.className = "warning";
    resultDiv.style.display = "block";
    resultDiv.textContent = "Analysing URL... Please wait.";

    try {
        const response = await fetch("http://127.0.0.1:5000/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to scan URL.");
        }

        // Display scan result
        resultDiv.innerHTML = "";

        const heading = document.createElement("h3");
        heading.textContent = data.status;
        resultDiv.appendChild(heading);

        const riskText = document.createElement("p");
        riskText.textContent = "Risk Level: " + data.risk;
        resultDiv.appendChild(riskText);

        const scoreText = document.createElement("p");
        scoreText.textContent = "Risk Score: " + data.score + "/100";
        resultDiv.appendChild(scoreText);

        const reasonsHeading = document.createElement("h4");
        reasonsHeading.textContent = "URL Analysis";
        resultDiv.appendChild(reasonsHeading);

        const reasonsList = document.createElement("ul");

        data.reasons.forEach(function(reason) {
            const item = document.createElement("li");
            item.textContent = reason;
            reasonsList.appendChild(item);
        });

        resultDiv.appendChild(reasonsList);

        const recommendationHeading = document.createElement("h4");
        recommendationHeading.textContent = "Safety Recommendation";
        resultDiv.appendChild(recommendationHeading);

        const recommendationText = document.createElement("p");
        recommendationText.textContent = data.recommendation;
        resultDiv.appendChild(recommendationText);

        // Apply the correct result colour
        if (data.risk === "High") {
            resultDiv.className = "danger";
        } else if (data.risk === "Medium") {
            resultDiv.className = "warning";
        } else {
            resultDiv.className = "safe";
        }

        // Keep the result box visible
        resultDiv.style.display = "block";
        resultDiv.style.visibility = "visible";
        resultDiv.style.opacity = "1";
        resultDiv.style.height = "auto";

        // Refresh history without removing the result
        loadScanHistory();

    } catch (error) {
        resultDiv.className = "danger";
        resultDiv.style.display = "block";
        resultDiv.style.visibility = "visible";
        resultDiv.style.opacity = "1";
        resultDiv.textContent =
            "Could not connect to LinkShield AI backend. " +
            "Please make sure the Flask server is running.";

        console.error(error);
    }
}


async function loadScanHistory() {
    const historyBody = document.getElementById("historyBody");

    if (!historyBody) {
        return;
    }

    try {
        const response = await fetch(
            "http://127.0.0.1:5000/history"
        );

        if (!response.ok) {
            throw new Error("Unable to load history");
        }

        const history = await response.json();

        historyBody.innerHTML = "";

        if (history.length === 0) {
            const row = historyBody.insertRow();
            const cell = row.insertCell();

            cell.colSpan = 5;
            cell.textContent = "No scan history available.";
            return;
        }

        history.forEach(function(item) {
            const row = historyBody.insertRow();

            const urlCell = row.insertCell();
            urlCell.textContent = item.url;

            const statusCell = row.insertCell();
            statusCell.textContent = item.status;

            const riskCell = row.insertCell();
            riskCell.textContent = item.risk;

            if (item.risk === "High") {
                riskCell.className = "history-high";
            } else if (item.risk === "Medium") {
                riskCell.className = "history-medium";
            } else {
                riskCell.className = "history-low";
            }

            const scoreCell = row.insertCell();
            scoreCell.textContent = item.score + "/100";

            const dateCell = row.insertCell();
            dateCell.textContent = item.scanned_at;
        });

    } catch (error) {
        historyBody.innerHTML = "";

        const row = historyBody.insertRow();
        const cell = row.insertCell();

        cell.colSpan = 5;
        cell.textContent =
            "Could not load history. Check that the Flask server is running.";

        console.error(error);
    }
}


// Load saved history when the page opens
loadScanHistory();

async function clearScanHistory() {
    const confirmClear = confirm(
        "Are you sure you want to clear all scan history?"
    );

    if (!confirmClear) {
        return;
    }

    try {
        const response = await fetch(
            "http://127.0.0.1:5000/clear-history",
            {
                method: "DELETE"
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Unable to clear history.");
        }

        await loadScanHistory();

        alert("Scan history cleared successfully!");

    } catch (error) {
        alert("Could not clear history. Please check the Flask server.");
        console.error(error);
    }
}

