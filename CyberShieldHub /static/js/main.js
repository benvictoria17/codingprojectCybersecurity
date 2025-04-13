// main.js - General JavaScript functionality for the application

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Add smooth scrolling to all links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                targetElement.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Show loading animation
    window.showLoading = function() {
        document.getElementById('loading-spinner').classList.remove('d-none');
    };

    // Hide loading animation
    window.hideLoading = function() {
        document.getElementById('loading-spinner').classList.add('d-none');
    };

    // Display results in a standardized way
    window.displayResults = function(resultsElement, data) {
        hideLoading();
        
        if (data.error) {
            resultsElement.innerHTML = `
                <div class="alert alert-danger" role="alert">
                    <i class="fas fa-exclamation-triangle me-2"></i> ${data.error}
                </div>
            `;
            return;
        }

        if (Array.isArray(data) && data.length === 0) {
            resultsElement.innerHTML = `
                <div class="alert alert-info" role="alert">
                    <i class="fas fa-info-circle me-2"></i> No issues found! Your system looks secure.
                </div>
            `;
            return;
        }

        // Clear previous results
        resultsElement.innerHTML = '';
        
        // If data is an array of items
        if (Array.isArray(data)) {
            const list = document.createElement('ul');
            list.className = 'list-group mb-4';
            
            data.forEach(item => {
                const listItem = document.createElement('li');
                listItem.className = 'list-group-item';
                
                if (typeof item === 'object') {
                    if (item.severity) {
                        let severityClass = 'bg-info';
                        if (item.severity === 'high') severityClass = 'bg-danger';
                        else if (item.severity === 'medium') severityClass = 'bg-warning';
                        else if (item.severity === 'low') severityClass = 'bg-success';
                        
                        listItem.innerHTML = `
                            <div class="d-flex justify-content-between align-items-center">
                                <span>${item.message || item.description || JSON.stringify(item)}</span>
                                <span class="badge ${severityClass}">${item.severity}</span>
                            </div>
                        `;
                    } else {
                        listItem.textContent = JSON.stringify(item);
                    }
                } else {
                    listItem.textContent = item;
                }
                
                list.appendChild(listItem);
            });
            
            resultsElement.appendChild(list);
        } 
        // If data is an object with categories
        else if (typeof data === 'object') {
            for (const [category, items] of Object.entries(data)) {
                if (items && (Array.isArray(items) ? items.length > 0 : Object.keys(items).length > 0)) {
                    const categoryTitle = document.createElement('h5');
                    categoryTitle.className = 'mt-4 mb-3';
                    categoryTitle.textContent = formatCategoryName(category);
                    resultsElement.appendChild(categoryTitle);
                    
                    const categoryList = document.createElement('ul');
                    categoryList.className = 'list-group mb-4';
                    
                    if (Array.isArray(items)) {
                        items.forEach(item => {
                            const listItem = document.createElement('li');
                            listItem.className = 'list-group-item';
                            
                            if (typeof item === 'object') {
                                listItem.textContent = JSON.stringify(item);
                            } else {
                                listItem.textContent = item;
                            }
                            
                            categoryList.appendChild(listItem);
                        });
                    } else if (typeof items === 'object') {
                        for (const [key, value] of Object.entries(items)) {
                            const listItem = document.createElement('li');
                            listItem.className = 'list-group-item';
                            
                            if (typeof value === 'object') {
                                listItem.innerHTML = `<strong>${key}</strong>: ${JSON.stringify(value)}`;
                            } else {
                                listItem.innerHTML = `<strong>${key}</strong>: ${value}`;
                            }
                            
                            categoryList.appendChild(listItem);
                        }
                    }
                    
                    resultsElement.appendChild(categoryList);
                }
            }
        }
    };

    // Helper function to format category names
    function formatCategoryName(name) {
        return name
            .replace(/_/g, ' ')
            .split(' ')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }
});
