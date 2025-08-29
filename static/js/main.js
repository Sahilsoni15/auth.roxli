// Main JavaScript file for Roxli Authentication

// Utility functions
function showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
        errorElement.textContent = message;
        errorElement.style.display = 'block';
    }
}

function hideError(elementId) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
        errorElement.style.display = 'none';
    }
}

// Avatar generation helper
function generateInitials(firstName, lastName) {
    return `${firstName.charAt(0).toUpperCase()}${lastName.charAt(0).toUpperCase()}`;
}

// File upload helper
function handleImageUpload(file, callback) {
    if (!file.type.startsWith('image/')) {
        alert('Please select an image file');
        return;
    }
    
    if (file.size > 5 * 1024 * 1024) { // 5MB limit
        alert('Image size should be less than 5MB');
        return;
    }
    
    const reader = new FileReader();
    reader.onload = (e) => callback(e.target.result);
    reader.readAsDataURL(file);
}

// API helpers
async function apiRequest(url, options = {}) {
    try {
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }
        
        return data;
    } catch (error) {
        console.error('API Request failed:', error);
        throw error;
    }
}

// Authentication functions
const RoxliAuth = {
    async signIn(options = {}) {
        return new Promise((resolve, reject) => {
            const popup = window.open('/popup', 'roxli-auth', 'width=400,height=600,scrollbars=yes,resizable=yes');
            
            const messageHandler = (event) => {
                if (event.origin !== window.location.origin) return;
                
                if (event.data.type === 'ROXLI_AUTH_SUCCESS') {
                    popup.close();
                    window.removeEventListener('message', messageHandler);
                    
                    // Save account to localStorage for multi-account support
                    const savedAccounts = JSON.parse(localStorage.getItem('roxli_accounts') || '[]');
                    const existingIndex = savedAccounts.findIndex(acc => acc.email === event.data.user.email);
                    if (existingIndex === -1) {
                        savedAccounts.push(event.data.user);
                    } else {
                        savedAccounts[existingIndex] = event.data.user;
                    }
                    localStorage.setItem('roxli_accounts', JSON.stringify(savedAccounts));
                    
                    if (options.onSuccess) {
                        options.onSuccess(event.data.user);
                    }
                    resolve(event.data.user);
                } else if (event.data.type === 'ROXLI_AUTH_ERROR') {
                    popup.close();
                    window.removeEventListener('message', messageHandler);
                    
                    if (options.onError) {
                        options.onError(event.data.error);
                    }
                    reject(new Error(event.data.error));
                }
            };
            
            window.addEventListener('message', messageHandler);
            
            // Handle popup closed manually
            const checkClosed = setInterval(() => {
                if (popup.closed) {
                    clearInterval(checkClosed);
                    window.removeEventListener('message', messageHandler);
                    
                    if (options.onError) {
                        options.onError('Popup closed');
                    }
                    reject(new Error('Popup closed'));
                }
            }, 1000);
        });
    },
    
    async getUser() {
        try {
            const data = await apiRequest('/api/user');
            return data.user;
        } catch (error) {
            return null;
        }
    },
    
    async signOut() {
        try {
            await apiRequest('/api/logout', { method: 'POST' });
            // Don't clear all accounts, just current session
            return true;
        } catch (error) {
            console.error('Logout failed:', error);
            return false;
        }
    },
    
    async switchAccount(email) {
        try {
            const response = await apiRequest('/api/switch-account', {
                method: 'POST',
                body: JSON.stringify({ email })
            });
            
            if (response.success) {
                // Update saved accounts
                const savedAccounts = JSON.parse(localStorage.getItem('roxli_accounts') || '[]');
                const accountIndex = savedAccounts.findIndex(acc => acc.email === email);
                if (accountIndex !== -1) {
                    savedAccounts[accountIndex] = response.user;
                    localStorage.setItem('roxli_accounts', JSON.stringify(savedAccounts));
                }
                
                return response.user;
            }
            return null;
        } catch (error) {
            console.error('Account switch failed:', error);
            return null;
        }
    },
    
    getSavedAccounts() {
        return JSON.parse(localStorage.getItem('roxli_accounts') || '[]');
    },
    
    removeSavedAccount(email) {
        const savedAccounts = JSON.parse(localStorage.getItem('roxli_accounts') || '[]');
        const filteredAccounts = savedAccounts.filter(acc => acc.email !== email);
        localStorage.setItem('roxli_accounts', JSON.stringify(filteredAccounts));
    }
};

// Make RoxliAuth available globally for integration
window.RoxliAuth = RoxliAuth;

// Form validation helpers
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@roxli\.in$/;
    return emailRegex.test(email);
}

function validatePassword(password) {
    return password.length >= 6;
}

function validateName(name) {
    return name.trim().length >= 2;
}

// Initialize page-specific functionality
document.addEventListener('DOMContentLoaded', function() {
    // Auto-focus first input on auth pages
    const firstInput = document.querySelector('input[type="text"], input[type="email"]');
    if (firstInput) {
        firstInput.focus();
    }
    
    // Handle Enter key on forms
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                const submitButton = form.querySelector('button[type="submit"]');
                if (submitButton) {
                    submitButton.click();
                }
            }
        });
    });
});

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { RoxliAuth, apiRequest, validateEmail, validatePassword, validateName };
}