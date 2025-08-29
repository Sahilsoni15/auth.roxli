/**
 * Roxli Authentication SDK
 * Easy integration for websites and applications
 */

(function(window) {
    'use strict';
    
    const ROXLI_BASE_URL = 'https://auth.roxli.in';
    
    class RoxliSDK {
        constructor() {
            this.baseUrl = ROXLI_BASE_URL;
            this.popup = null;
        }
        
        /**
         * Sign in with Roxli
         * @param {Object} options - Configuration options
         * @param {Function} options.onSuccess - Success callback (user, token)
         * @param {Function} options.onError - Error callback
         * @param {string} options.redirectUrl - Redirect URL after success
         */
        signIn(options = {}) {
            return new Promise((resolve, reject) => {
                // Close existing popup if any
                if (this.popup && !this.popup.closed) {
                    this.popup.close();
                }
                
                // Open popup
                this.popup = window.open(
                    `${this.baseUrl}/popup`,
                    'roxli-auth',
                    'width=400,height=600,scrollbars=yes,resizable=yes,location=no,menubar=no,toolbar=no'
                );
                
                // Handle popup messages
                const messageHandler = (event) => {
                    if (event.origin !== this.baseUrl.replace(/:\d+$/, '')) {
                        // Allow localhost with any port for development
                        if (!event.origin.startsWith('http://localhost')) {
                            return;
                        }
                    }
                    
                    if (event.data.type === 'ROXLI_AUTH_SUCCESS') {
                        this.popup.close();
                        window.removeEventListener('message', messageHandler);
                        
                        const user = event.data.user;
                        const token = event.data.token;
                        
                        // Store user data and token
                        this.setUser(user);
                        if (token) {
                            localStorage.setItem('roxli_token', token);
                        }
                        
                        // Call success callback with user and token
                        if (options.onSuccess) {
                            options.onSuccess(user, token);
                        }
                        
                        // Redirect if specified
                        if (options.redirectUrl) {
                            window.location.href = options.redirectUrl;
                        }
                        
                        resolve(user);
                        
                    } else if (event.data.type === 'ROXLI_AUTH_ERROR') {
                        this.popup.close();
                        window.removeEventListener('message', messageHandler);
                        
                        const error = event.data.error;
                        
                        if (options.onError) {
                            options.onError(error);
                        }
                        
                        reject(new Error(error));
                    }
                };
                
                window.addEventListener('message', messageHandler);
                
                // Handle popup closed manually
                const checkClosed = setInterval(() => {
                    if (this.popup.closed) {
                        clearInterval(checkClosed);
                        window.removeEventListener('message', messageHandler);
                        
                        const error = 'Authentication cancelled';
                        
                        if (options.onError) {
                            options.onError(error);
                        }
                        
                        reject(new Error(error));
                    }
                }, 1000);
            });
        }
        
        /**
         * Get current user
         * @returns {Object|null} User object or null if not logged in
         */
        getUser() {
            try {
                const userData = localStorage.getItem('roxli_user');
                return userData ? JSON.parse(userData) : null;
            } catch (error) {
                console.error('Error getting user data:', error);
                return null;
            }
        }
        
        /**
         * Get current token
         * @returns {string|null} Token or null if not logged in
         */
        getToken() {
            return localStorage.getItem('roxli_token');
        }
        
        /**
         * Set user data
         * @param {Object} user - User object
         */
        setUser(user) {
            try {
                localStorage.setItem('roxli_user', JSON.stringify(user));
                
                // Dispatch custom event
                window.dispatchEvent(new CustomEvent('roxli:userChanged', {
                    detail: { user }
                }));
            } catch (error) {
                console.error('Error setting user data:', error);
            }
        }
        
        /**
         * Sign out current user
         */
        signOut() {
            return new Promise((resolve) => {
                try {
                    // Clear local storage
                    localStorage.removeItem('roxli_user');
                    localStorage.removeItem('roxli_token');
                    
                    // Make logout request to server
                    fetch(`${this.baseUrl}/api/logout`, {
                        method: 'POST',
                        credentials: 'include'
                    }).finally(() => {
                        // Dispatch custom event
                        window.dispatchEvent(new CustomEvent('roxli:userChanged', {
                            detail: { user: null }
                        }));
                        
                        resolve();
                    });
                } catch (error) {
                    console.error('Error during sign out:', error);
                    resolve();
                }
            });
        }
        
        /**
         * Check if user is authenticated
         * @returns {boolean}
         */
        isAuthenticated() {
            return this.getUser() !== null;
        }
        
        /**
         * Verify token with server
         * @param {string} token - Token to verify
         * @returns {Promise<Object>} User object if valid
         */
        async verifyToken(token) {
            try {
                const response = await fetch(`${this.baseUrl}/api/verify`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ token })
                });
                
                if (!response.ok) {
                    throw new Error('Token verification failed');
                }
                
                const data = await response.json();
                return data.user;
            } catch (error) {
                console.error('Token verification error:', error);
                throw error;
            }
        }
        
        /**
         * Listen for authentication state changes
         * @param {Function} callback - Callback function
         */
        onAuthStateChanged(callback) {
            window.addEventListener('roxli:userChanged', (event) => {
                callback(event.detail.user);
            });
            
            // Call immediately with current user
            callback(this.getUser());
        }
    }
    
    // Create global instance
    const RoxliAuth = new RoxliSDK();
    
    // Expose to global scope
    window.RoxliAuth = RoxliAuth;
    
    // AMD support
    if (typeof define === 'function' && define.amd) {
        define(function() {
            return RoxliAuth;
        });
    }
    
    // CommonJS support
    if (typeof module !== 'undefined' && module.exports) {
        module.exports = RoxliAuth;
    }
    
})(window);