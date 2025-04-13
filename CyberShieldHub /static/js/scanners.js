// scanners.js - JavaScript functionality for the scanner pages

document.addEventListener('DOMContentLoaded', function() {
    // OSINT Scanner Form
    const osintForm = document.getElementById('osint-form');
    if (osintForm) {
        osintForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const resultsElement = document.getElementById('osint-results');
            showLoading();
            
            fetch('/api/osint', {
                method: 'POST',
                body: new FormData(osintForm)
            })
            .then(response => response.json())
            .then(data => {
                displayResults(resultsElement, data);
            })
            .catch(error => {
                hideLoading();
                resultsElement.innerHTML = `
                    <div class="alert alert-danger" role="alert">
                        <i class="fas fa-exclamation-triangle me-2"></i> Error: ${error.message}
                    </div>
                `;
            });
        });
    }

    // Website Scanner Form
    const websiteForm = document.getElementById('website-scanner-form');
    if (websiteForm) {
        websiteForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const resultsElement = document.getElementById('website-scanner-results');
            showLoading();
            
            fetch('/api/scan-website', {
                method: 'POST',
                body: new FormData(websiteForm)
            })
            .then(response => response.json())
            .then(data => {
                displayResults(resultsElement, data);
            })
            .catch(error => {
                hideLoading();
                resultsElement.innerHTML = `
                    <div class="alert alert-danger" role="alert">
                        <i class="fas fa-exclamation-triangle me-2"></i> Error: ${error.message}
                    </div>
                `;
            });
        });
    }

    // Server Scanner Form
    const serverForm = document.getElementById('server-scanner-form');
    if (serverForm) {
        serverForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const resultsElement = document.getElementById('server-scanner-results');
            showLoading();
            
            fetch('/api/scan-server', {
                method: 'POST',
                body: new FormData(serverForm)
            })
            .then(response => response.json())
            .then(data => {
                displayResults(resultsElement, data);
            })
            .catch(error => {
                hideLoading();
                resultsElement.innerHTML = `
                    <div class="alert alert-danger" role="alert">
                        <i class="fas fa-exclamation-triangle me-2"></i> Error: ${error.message}
                    </div>
                `;
            });
        });
    }

    // Network Scanner Form
    const networkForm = document.getElementById('network-scanner-form');
    if (networkForm) {
        networkForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const resultsElement = document.getElementById('network-scanner-results');
            showLoading();
            
            fetch('/api/scan-network', {
                method: 'POST',
                body: new FormData(networkForm)
            })
            .then(response => response.json())
            .then(data => {
                displayResults(resultsElement, data);
            })
            .catch(error => {
                hideLoading();
                resultsElement.innerHTML = `
                    <div class="alert alert-danger" role="alert">
                        <i class="fas fa-exclamation-triangle me-2"></i> Error: ${error.message}
                    </div>
                `;
            });
        });
    }

    // Database Scanner Form
    const databaseForm = document.getElementById('database-scanner-form');
    if (databaseForm) {
        databaseForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const resultsElement = document.getElementById('database-scanner-results');
            showLoading();
            
            fetch('/api/scan-database', {
                method: 'POST',
                body: new FormData(databaseForm)
            })
            .then(response => response.json())
            .then(data => {
                displayResults(resultsElement, data);
            })
            .catch(error => {
                hideLoading();
                resultsElement.innerHTML = `
                    <div class="alert alert-danger" role="alert">
                        <i class="fas fa-exclamation-triangle me-2"></i> Error: ${error.message}
                    </div>
                `;
            });
        });
    }

    // Cloud Scanner Form
    const cloudForm = document.getElementById('cloud-scanner-form');
    if (cloudForm) {
        cloudForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const resultsElement = document.getElementById('cloud-scanner-results');
            showLoading();
            
            fetch('/api/scan-cloud', {
                method: 'POST',
                body: new FormData(cloudForm)
            })
            .then(response => response.json())
            .then(data => {
                displayResults(resultsElement, data);
            })
            .catch(error => {
                hideLoading();
                resultsElement.innerHTML = `
                    <div class="alert alert-danger" role="alert">
                        <i class="fas fa-exclamation-triangle me-2"></i> Error: ${error.message}
                    </div>
                `;
            });
        });
    }

    // Google Dorking Form
    const dorkingForm = document.getElementById('google-dorking-form');
    if (dorkingForm) {
        dorkingForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const resultsElement = document.getElementById('google-dorking-results');
            showLoading();
            
            fetch('/api/google-dork', {
                method: 'POST',
                body: new FormData(dorkingForm)
            })
            .then(response => response.json())
            .then(data => {
                displayResults(resultsElement, data);
            })
            .catch(error => {
                hideLoading();
                resultsElement.innerHTML = `
                    <div class="alert alert-danger" role="alert">
                        <i class="fas fa-exclamation-triangle me-2"></i> Error: ${error.message}
                    </div>
                `;
            });
        });
    }
});
