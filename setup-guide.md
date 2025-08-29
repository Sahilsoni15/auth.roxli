# 🚀 Roxli Authentication Setup Guide

## Quick Setup (5 minutes)

### Step 1: Firebase Setup
1. Go to [Firebase Console](https://console.firebase.google.com/)
2. Create new project: "Roxli Auth"
3. Enable **Realtime Database**
4. Set rules to:
```json
{
  "rules": {
    ".read": true,
    ".write": true,
    "users": {
      ".indexOn": ["email"]
    }
  }
}
```
5. Generate service account key:
   - Project Settings → Service Accounts
   - Generate new private key
   - Save as `firebase-key.json`

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 3: Configure
1. Copy `firebase-key.json` to project root
2. Update database URL in `app.py`:
```python
'databaseURL': 'https://YOUR-PROJECT-ID-default-rtdb.firebaseio.com/'
```

### Step 4: Run Application
```bash
python app.py
```

Visit: `http://localhost:5000`

## Integration in Any Website

### Basic Integration
```html
<script src="http://localhost:5000/static/js/roxli-sdk.js"></script>
<button onclick="signInWithRoxli()">Sign in with Roxli</button>

<script>
function signInWithRoxli() {
    RoxliAuth.signIn({
        onSuccess: function(user) {
            console.log('User:', user);
        }
    });
}
</script>
```

### Features Available
- ✅ Multi-account switching
- ✅ Auto avatar generation
- ✅ Custom avatar upload
- ✅ Popup login
- ✅ Device account memory
- ✅ Dark/Light themes

## Troubleshooting

### Firebase Error 400
- Check database rules are set correctly
- Ensure indexing is enabled for email field
- Verify database URL is correct

### Registration Issues
- Ensure email ends with @roxli.in
- Check Firebase permissions
- Verify network connectivity

## Production Deployment
1. Update `ROXLI_BASE_URL` in `roxli-sdk.js`
2. Set up HTTPS
3. Use production Firebase project
4. Deploy with Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```