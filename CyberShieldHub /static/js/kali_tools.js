// JavaScript for Kali Linux Tools functionality

document.addEventListener('DOMContentLoaded', function() {
    // Functions for Kali tools page
    function formatSeverity(severity) {
        let icon = '';
        let colorClass = '';
        
        switch (severity.toLowerCase()) {
            case 'low':
                icon = '<i class="fas fa-info-circle"></i>';
                colorClass = 'info';
                break;
            case 'medium':
                icon = '<i class="fas fa-exclamation-circle"></i>';
                colorClass = 'warning';
                break;
            case 'high':
                icon = '<i class="fas fa-exclamation-triangle"></i>';
                colorClass = 'danger';
                break;
            default:
                icon = '<i class="fas fa-info-circle"></i>';
                colorClass = 'secondary';
        }
        
        return {
            icon: icon,
            color_class: colorClass,
            label: severity.charAt(0).toUpperCase() + severity.slice(1)
        };
    }
    
    // Format category name (convert snake_case to Title Case)
    function formatCategoryName(name) {
        if (!name) return '';
        return name
            .split('_')
            .map(word => word.charAt(0).toUpperCase() + word.slice(1))
            .join(' ');
    }
    
    // Get color class for difficulty level
    function getDifficultyColor(difficulty) {
        switch ((difficulty || '').toLowerCase()) {
            case 'easy':
                return 'success';
            case 'medium':
                return 'info';
            case 'hard':
                return 'warning';
            case 'very hard':
                return 'danger';
            default:
                return 'secondary';
        }
    }
    
    // Show tool description in a pretty format
    function showToolDescription(tool) {
        if (!tool) return '';
        
        let html = `
            <div class="card mb-3">
                <div class="card-header bg-dark text-white">
                    <h5 class="mb-0">${tool.name}</h5>
                </div>
                <div class="card-body">
                    <p>${tool.description}</p>
                    <div class="alert alert-info">
                        <strong>Kid-Friendly Explanation:</strong> ${tool.kid_friendly_explanation}
                    </div>
                    <div class="row mt-3">
                        <div class="col-md-6">
                            <h6>Difficulty Level</h6>
                            <span class="badge bg-${getDifficultyColor(tool.difficulty)}">${tool.difficulty}</span>
                        </div>
                        <div class="col-md-6">
                            <h6>Example Command</h6>
                            <pre><code>${tool.example_command}</code></pre>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        return html;
    }
    
    // Make global functions available
    window.kaliTools = {
        formatSeverity: formatSeverity,
        formatCategoryName: formatCategoryName,
        getDifficultyColor: getDifficultyColor,
        showToolDescription: showToolDescription
    };
});