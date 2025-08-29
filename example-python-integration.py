"""
Example Python Flask Integration with Roxli Authentication
This shows how to integrate Roxli auth into a Python web application
"""

from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
import requests
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# Roxli server configuration
ROXLI_BASE_URL = 'http://localhost:5000'

# HTML template for the example app
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Python Flask + Roxli Auth Example</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .auth-section { text-align: center; padding: 40px; background: #f8f9fa; border-radius: 8px; }
        .user-section { padding: 20px; background: #e8f5e8; border-radius: 8px; }
        .roxli-btn { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 12px 24px; border-radius: 6px;
            cursor: pointer; font-weight: 600; font-size: 16px;
        }
        .user-card { display: flex; align-items: center; gap: 15px; }
        .avatar { width: 60px; height: 60px; border-radius: 50%; }
        .protected-content { background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; }
    </style>
</head>
<body>
    <h1>🐍 Python Flask + Roxli Authentication</h1>
    
    {% if user %}
    <div class="user-section">
        <h2>✅ Welcome, {{ user.firstName }}!</h2>
        <div class="user-card">
            <img src="{{ user.avatar }}" alt="Avatar" class="avatar">
            <div>
                <h3>{{ user.firstName }} {{ user.lastName }}</h3>
                <p>{{ user.email }}</p>
                <p><strong>User ID:</strong> {{ user.id }}</p>
            </div>
        </div>
        
        <div class="protected-content">
            <h3>🔒 Protected Content</h3>
            <p>This content is only visible to authenticated users!</p>
            <p>You can now access protected routes and user-specific data.</p>
        </div>
        
        <button onclick="signOut()" style="background: #dc3545; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">
            Sign Out
        </button>
        <button onclick="switchAccount()" style="background: #6c757d; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-left: 10px;">
            Switch Account
        </button>
    </div>
    {% else %}
    <div class="auth-section">
        <h2>🔐 Authentication Required</h2>
        <p>Please sign in with your Roxli account to continue</p>
        <button onclick="signInWithRoxli()" class="roxli-btn">
            🔑 Sign in with Roxli
        </button>
    </div>
    {% endif %}
    
    <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 8px;">
        <h3>📋 Integration Steps Used:</h3>
        <ol>
            <li><strong>Frontend:</strong> Include Roxli SDK and handle popup login</li>
            <li><strong>Token Verification:</strong> Send token to Flask backend for verification</li>
            <li><strong>Session Management:</strong> Store user data in Flask session</li>
            <li><strong>Protected Routes:</strong> Check authentication before serving content</li>
        </ol>
    </div>

    <!-- Include Roxli SDK -->
    <script src="{{ roxli_base_url }}/static/js/roxli-sdk.js"></script>
    
    <script>
        function signInWithRoxli() {
            RoxliAuth.signIn({
                onSuccess: function(user, token) {
                    // Send token to Flask backend for verification
                    fetch('/verify-roxli-token', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: token })
                    })
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            // Reload page to show authenticated state
                            window.location.reload();
                        } else {
                            alert('Authentication failed: ' + data.error);
                        }
                    })
                    .catch(error => {
                        console.error('Error:', error);
                        alert('Authentication failed');
                    });
                },
                onError: function(error) {
                    alert('Login failed: ' + error);
                }
            });
        }
        
        function signOut() {
            // Sign out from Roxli
            RoxliAuth.signOut().then(() => {
                // Clear Flask session
                fetch('/logout', { method: 'POST' })
                    .then(() => window.location.reload());
            });
        }
        
        function switchAccount() {
            window.open('{{ roxli_base_url }}/switch-account', 'switch', 'width=500,height=600');
        }
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    """Main page - shows login or user info based on authentication"""
    user = session.get('user')
    return render_template_string(HTML_TEMPLATE, user=user, roxli_base_url=ROXLI_BASE_URL)

@app.route('/verify-roxli-token', methods=['POST'])
def verify_roxli_token():
    """Verify Roxli token and create Flask session"""
    try:
        data = request.json
        token = data.get('token')
        
        if not token:
            return jsonify({'success': False, 'error': 'Token required'}), 400
        
        # Verify token with Roxli server
        response = requests.post(f'{ROXLI_BASE_URL}/api/verify', 
            json={'token': token},
            timeout=10
        )
        
        if response.status_code == 200:
            user_data = response.json()
            
            # Store user in Flask session
            session['user'] = user_data['user']
            session['roxli_token'] = token
            
            return jsonify({
                'success': True,
                'user': user_data['user']
            })
        else:
            return jsonify({
                'success': False, 
                'error': 'Invalid token'
            }), 401
            
    except requests.RequestException as e:
        return jsonify({
            'success': False, 
            'error': f'Verification failed: {str(e)}'
        }), 500
    except Exception as e:
        return jsonify({
            'success': False, 
            'error': f'Server error: {str(e)}'
        }), 500

@app.route('/logout', methods=['POST'])
def logout():
    """Clear Flask session"""
    session.clear()
    return jsonify({'success': True})

@app.route('/protected')
def protected():
    """Example protected route"""
    if 'user' not in session:
        return redirect(url_for('index'))
    
    user = session['user']
    return f'''
    <h1>🔒 Protected Page</h1>
    <p>Hello {user['firstName']}! This is a protected route.</p>
    <p>Only authenticated users can see this content.</p>
    <a href="/">← Back to Home</a>
    '''

@app.route('/api/user-data')
def get_user_data():
    """API endpoint that returns user data (requires authentication)"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    return jsonify({
        'user': session['user'],
        'message': 'This is protected user data from Flask backend'
    })

if __name__ == '__main__':
    print("🚀 Starting Python Flask + Roxli Auth Example")
    print("📍 Make sure Roxli server is running on http://localhost:5000")
    print("🌐 This app will run on http://localhost:3000")
    print()
    
    app.run(debug=True, port=3000)