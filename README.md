# ngx-http-auth-jwt-gateway

A JWT Authentication Gateway for NGINX with Google OAuth support. Works seamlessly with the [ngx-http-auth-jwt-module](https://github.com/TeslaGov/ngx-http-auth-jwt-module).

## Quick Start with Docker Compose

The easiest way to get started is using Docker Compose with the pre-built NGINX JWT module image.

### Prerequisites

- Docker and Docker Compose
- Google OAuth credentials ([Get them here](https://console.cloud.google.com/apis/credentials))

### 1. Clone and Setup

```bash
git clone https://github.com/w453y/ngx-http-auth-jwt-gateway.git
cd ngx-http-auth-jwt-gateway

# Create environment file
cp .env.example .env
```

### 2. Generate JWT Secret

Generate a secure hex-encoded secret for JWT signing:

```bash
# Generate 256-bit key for HS256 (recommended)
openssl rand -hex 32
```

Save this value - you'll use it in both `.env` and `nginx.conf`.

### 3. Configure Environment

Edit `.env` with your settings:

```env
# Google OAuth
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_CALLBACK_URL=http://auth.example.com/auth/google/callback

# Session
SESSION_SECRET=your-session-secret-here

# User Subsets
SUBSETS=admin,user
SUBSET_admin_EMAILS=admin@company.com
SUBSET_user_EMAILS=user1@company.com,user2@company.com

# JWT Configuration (use the hex secret from step 2)
JWT_SECRET_auth_token=your-hex-secret-from-openssl
JWT_ALGORITHM_auth_token=HS256
JWT_EXPIRES_auth_token=24h
JWT_DOMAIN_auth_token=.example.com

# Cookies per subset
SUBSET_admin_COOKIES=auth-token
SUBSET_user_COOKIES=auth-token
```

### 4. Update NGINX Configuration

Edit `nginx/nginx.conf` and set your JWT secret (same hex value from step 2):

```nginx
# IMPORTANT: Replace with your actual hex secret from step 2
auth_jwt_key 'your-hex-secret-from-openssl';
```

Update domain names to match your setup:
- `auth.example.com` - Auth gateway
- `app.example.com` - Your protected application

### 5. Start Services

```bash
docker compose up -d
```

View logs:
```bash
docker compose logs -f
```

### 6. Access Your Application

1. Visit `http://app.example.com` (or your configured domain)
2. NGINX redirects to `http://auth.example.com` for login
3. Log in with Google account
4. After successful authentication, redirected back with JWT cookie
5. Access your protected application

## How It Works

```
User → NGINX (JWT Check) → Protected App
         ↓ (no JWT)
     Auth Gateway
     1. Google OAuth
     2. Verify email in subset
     3. Generate JWT
     4. Set cookie
     5. Redirect back
```

## JWT Secret Configuration

The JWT secret must be the same in both:

1. **Auth Gateway** (`.env`):
   ```env
   JWT_SECRET_auth_token=abc123def456...
   ```

2. **NGINX** (`nginx/nginx.conf`):
   ```nginx
   auth_jwt_key 'abc123def456...';
   ```

**Important**: Always use the hex-encoded format. Generate with:
```bash
openssl rand -hex 32  # For HS256
openssl rand -hex 48  # For HS384
openssl rand -hex 64  # For HS512
```

## Architecture

The system consists of three components:

1. **Auth Gateway** (this project) - Handles Google OAuth and JWT generation
2. **NGINX with JWT Module** - Validates JWTs and protects applications
3. **Your Application** - Protected backend service

## Security Notes

⚠️ **Production Requirements**:
- Always use HTTPS in production
- Use strong, randomly generated JWT secrets
- Set appropriate cookie domains
- Keep HttpOnly and SameSite cookie flags enabled
- Regularly rotate secrets

## Configuration Reference

### Environment Variables

**Server**:
- `PORT` - Server port (default: 3000)
- `SESSION_SECRET` - Express session secret (required)

**Google OAuth**:
- `GOOGLE_CLIENT_ID` - OAuth client ID (required)
- `GOOGLE_CLIENT_SECRET` - OAuth client secret (required)
- `GOOGLE_CALLBACK_URL` - OAuth callback URL (required)

**Subsets**:
- `SUBSETS` - Comma-separated subset names
- `SUBSET_{name}_EMAILS` - Emails for subset
- `SUBSET_{name}_COOKIES` - Cookies to set for subset

**JWT** (replace `{cookie}` with cookie name using underscores):
- `JWT_SECRET_{cookie}` - JWT signing secret (hex-encoded)
- `JWT_ALGORITHM_{cookie}` - Algorithm: HS256, HS384, HS512 (default: HS256)
- `JWT_EXPIRES_{cookie}` - Expiration time (default: 24h)
- `JWT_DOMAIN_{cookie}` - Cookie domain (e.g., .example.com)

### NGINX Directives

Key directives for `ngx_http_auth_jwt_module`:

```nginx
# Load the module
load_module /usr/lib/nginx/modules/ngx_http_auth_jwt_module.so;

http {
    # JWT secret (hex-encoded)
    auth_jwt_key 'your-hex-secret';
    
    # Algorithm (must match auth gateway)
    auth_jwt_algorithm HS256;
    
    # Cookie name to read JWT from
    auth_jwt_location 'COOKIE=auth-token';
    
    # Redirect to login URL when JWT invalid
    auth_jwt_redirect on;
    auth_jwt_loginurl 'http://auth.example.com';
    
    server {
        # Enable JWT authentication
        auth_jwt_enabled on;
        
        # Extract claims as variables
        auth_jwt_extract_var_claims sub email name;
        
        location / {
            # Pass claims to upstream
            proxy_set_header X-User-Email $jwt_claim_email;
            proxy_pass http://upstream;
        }
    }
}
```

## API Endpoints

- `GET /` - Login page
- `GET /auth/google` - Initiate Google OAuth
- `GET /auth/google/callback` - OAuth callback
- `GET /logout` - Logout and clear cookies
- `GET /health` - Health check

## Troubleshooting

**"This email is not authorized"**
- Add email to `SUBSET_{name}_EMAILS` in `.env`

**Cookie not being set**
- Check `JWT_DOMAIN` matches your domain
- Use HTTPS in production
- Verify browser allows cookies

**NGINX returns 401**
- Verify JWT secret matches in both `.env` and `nginx.conf`
- Check algorithm matches (HS256)
- Ensure cookie name matches `auth_jwt_location`

**Return URL not working**
- Ensure `return_url` parameter is passed correctly
- Check URL encoding

## License

MIT

## Related Projects

- [ngx-http-auth-jwt-module](https://github.com/TeslaGov/ngx-http-auth-jwt-module) - NGINX JWT authentication module
- [Docker Image: w453y/ngx_http_auth_jwt_module](https://hub.docker.com/r/w453y/ngx_http_auth_jwt_module) - Pre-built NGINX with JWT module
