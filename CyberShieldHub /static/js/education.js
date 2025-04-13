// education.js - JavaScript functionality for the education pages

document.addEventListener('DOMContentLoaded', function() {
    // Initialize all popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl, {
            trigger: 'focus',
            html: true
        });
    });

    // Handle quiz submissions
    const quizForms = document.querySelectorAll('.quiz-form');
    quizForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const quizId = this.getAttribute('data-quiz-id');
            const resultElement = document.getElementById(`quiz-result-${quizId}`);
            
            // Get all the answers
            const answers = {};
            this.querySelectorAll('input[type="radio"]:checked').forEach(radio => {
                answers[radio.name] = radio.value;
            });
            
            // Get correct answers (stored in data attributes in the form)
            const correctAnswers = JSON.parse(this.getAttribute('data-correct-answers'));
            
            // Calculate score
            let score = 0;
            let totalQuestions = Object.keys(correctAnswers).length;
            
            for (const [question, answer] of Object.entries(answers)) {
                if (correctAnswers[question] === answer) {
                    score++;
                }
            }
            
            // Determine if passed (70% or higher)
            const percentage = (score / totalQuestions) * 100;
            const passed = percentage >= 70;
            
            // Display result with appropriate styling
            resultElement.innerHTML = `
                <div class="alert ${passed ? 'alert-success' : 'alert-warning'} mt-3">
                    <h5 class="alert-heading">${passed ? 'Great job!' : 'Keep trying!'}</h5>
                    <p>You got ${score} out of ${totalQuestions} questions correct (${percentage.toFixed(0)}%).</p>
                    ${passed ? '<p>You have a good understanding of this topic!</p>' : '<p>Review the material and try again.</p>'}
                </div>
            `;
            
            // Show detailed feedback
            const feedbackElement = document.getElementById(`quiz-feedback-${quizId}`);
            if (feedbackElement) {
                let feedbackHtml = '<h5 class="mt-4">Question Feedback:</h5><ul class="list-group">';
                
                for (const [question, correctAnswer] of Object.entries(correctAnswers)) {
                    const userAnswer = answers[question] || 'Not answered';
                    const isCorrect = userAnswer === correctAnswer;
                    
                    // Get question text
                    const questionElement = document.querySelector(`label[for="${question}"]`);
                    const questionText = questionElement ? questionElement.textContent : question;
                    
                    // Get correct answer text
                    const correctAnswerElement = document.querySelector(`input[name="${question}"][value="${correctAnswer}"]`);
                    const correctAnswerLabel = correctAnswerElement ? 
                        document.querySelector(`label[for="${correctAnswerElement.id}"]`).textContent : 
                        correctAnswer;
                    
                    feedbackHtml += `
                        <li class="list-group-item ${isCorrect ? 'list-group-item-success' : 'list-group-item-danger'}">
                            <strong>${questionText}</strong><br>
                            Your answer: ${userAnswer}<br>
                            ${!isCorrect ? `Correct answer: ${correctAnswerLabel}` : ''}
                        </li>
                    `;
                }
                
                feedbackHtml += '</ul>';
                feedbackElement.innerHTML = feedbackHtml;
            }
            
            // Scroll to results
            resultElement.scrollIntoView({ behavior: 'smooth' });
        });
    });

    // Interactive examples
    const interactiveExamples = document.querySelectorAll('.interactive-example');
    interactiveExamples.forEach(example => {
        const codeBlock = example.querySelector('code');
        const runButton = example.querySelector('.run-example');
        const resultElement = example.querySelector('.example-result');
        
        if (runButton && resultElement) {
            runButton.addEventListener('click', function() {
                // Get the code
                const code = codeBlock ? codeBlock.textContent : '';
                
                // For simple examples, we can simulate execution
                switch (example.getAttribute('data-example-type')) {
                    case 'phishing-url':
                        simulatePhishingUrlCheck(code, resultElement);
                        break;
                    case 'password-strength':
                        simulatePasswordStrengthCheck(code, resultElement);
                        break;
                    case 's3-config':
                        simulateS3ConfigCheck(code, resultElement);
                        break;
                    default:
                        resultElement.innerHTML = `<div class="alert alert-info">Example execution simulated!</div>`;
                }
            });
        }
    });

    // Helper functions for interactive examples
    function simulatePhishingUrlCheck(url, resultElement) {
        const redFlags = [];
        
        if (url.includes('paypa1.com') || url.includes('amaz0n') || url.includes('g00gle')) {
            redFlags.push('Lookalike domain with numbers instead of letters');
        }
        
        if (url.includes('secure') || url.includes('login') || url.includes('account')) {
            redFlags.push('Uses security-related words to seem trustworthy');
        }
        
        if (url.includes('http://') && !url.includes('https://')) {
            redFlags.push('Uses HTTP instead of secure HTTPS');
        }
        
        if (url.includes('.xyz') || url.includes('.tk') || url.includes('.ml')) {
            redFlags.push('Uses unusual or free top-level domain');
        }
        
        if (redFlags.length > 0) {
            resultElement.innerHTML = `
                <div class="alert alert-danger">
                    <h5><i class="fas fa-exclamation-triangle"></i> Warning! This might be a phishing website.</h5>
                    <p>Red flags found:</p>
                    <ul>
                        ${redFlags.map(flag => `<li>${flag}</li>`).join('')}
                    </ul>
                </div>
            `;
        } else {
            resultElement.innerHTML = `
                <div class="alert alert-success">
                    <h5><i class="fas fa-check-circle"></i> No obvious phishing signs detected</h5>
                    <p>But always be careful! Real security tools check more things.</p>
                </div>
            `;
        }
    }

    function simulatePasswordStrengthCheck(password, resultElement) {
        // Simple password strength check
        let strength = 0;
        let feedback = [];
        
        if (password.length < 8) {
            feedback.push('Password is too short (should be at least 8 characters)');
        } else {
            strength += 1;
        }
        
        if (password.match(/[A-Z]/)) {
            strength += 1;
        } else {
            feedback.push('Add uppercase letters (like A, B, C)');
        }
        
        if (password.match(/[a-z]/)) {
            strength += 1;
        } else {
            feedback.push('Add lowercase letters (like a, b, c)');
        }
        
        if (password.match(/[0-9]/)) {
            strength += 1;
        } else {
            feedback.push('Add numbers (like 1, 2, 3)');
        }
        
        if (password.match(/[^A-Za-z0-9]/)) {
            strength += 1;
        } else {
            feedback.push('Add special characters (like !, @, #)');
        }
        
        // Common passwords check
        const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'welcome', 'football'];
        if (commonPasswords.includes(password.toLowerCase())) {
            strength = 0;
            feedback = ['This is a very common password. It\'s not safe!'];
        }
        
        let strengthText = '';
        let strengthClass = '';
        
        if (strength <= 1) {
            strengthText = 'Very Weak';
            strengthClass = 'bg-danger';
        } else if (strength <= 2) {
            strengthText = 'Weak';
            strengthClass = 'bg-warning';
        } else if (strength <= 3) {
            strengthText = 'Medium';
            strengthClass = 'bg-info';
        } else if (strength <= 4) {
            strengthText = 'Strong';
            strengthClass = 'bg-primary';
        } else {
            strengthText = 'Very Strong';
            strengthClass = 'bg-success';
        }
        
        resultElement.innerHTML = `
            <h5 class="mt-3">Password Strength: ${strengthText}</h5>
            <div class="progress">
                <div class="progress-bar ${strengthClass}" role="progressbar" style="width: ${strength * 20}%" 
                     aria-valuenow="${strength}" aria-valuemin="0" aria-valuemax="5"></div>
            </div>
            ${feedback.length > 0 ? `
                <div class="mt-3">
                    <p>How to make it stronger:</p>
                    <ul>
                        ${feedback.map(item => `<li>${item}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
        `;
    }

    function simulateS3ConfigCheck(config, resultElement) {
        const issues = [];
        
        if (config.includes('"PublicAccessBlock": false') || config.includes('"BlockPublicAcls": false')) {
            issues.push('Public access is not blocked - anyone might be able to access your files');
        }
        
        if (config.includes('"Versioning": "Disabled"') || !config.includes('"Versioning":')) {
            issues.push('Versioning is disabled - you can\'t recover old versions if files are changed or deleted');
        }
        
        if (!config.includes('"ServerSideEncryption":') || config.includes('"ServerSideEncryption": "Disabled"')) {
            issues.push('Server-side encryption is not enabled - your files are not protected by encryption');
        }
        
        if (issues.length > 0) {
            resultElement.innerHTML = `
                <div class="alert alert-warning">
                    <h5><i class="fas fa-exclamation-triangle"></i> Security issues found!</h5>
                    <ul>
                        ${issues.map(issue => `<li>${issue}</li>`).join('')}
                    </ul>
                </div>
            `;
        } else {
            resultElement.innerHTML = `
                <div class="alert alert-success">
                    <h5><i class="fas fa-check-circle"></i> Configuration looks secure!</h5>
                    <p>The S3 bucket has good security settings.</p>
                </div>
            `;
        }
    }
});
