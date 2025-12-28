# ngx-http-auth-jwt-gateway

A JWT Authentication Gateway for NGINX with Google OAuth support and flexible subset-based user management. Works seamlessly with the [ngx-http-auth-jwt-module](https://github.com/TeslaGov/ngx-http-auth-jwt-module).

## Features

- **Google OAuth Login** - Single sign-on with Google accounts
- **Subset-based User Management** - Organize users into groups (A, B, C, ..., n)
- **Flexible Cookie Configuration** - Different JWT tokens/cookies per subset
- **Seamless NGINX Integration** - Works with ngx-http-auth-jwt-module
- **Return URL Handling** - Maintains redirect URL throughout auth flow
- **Docker Ready** - Fully containerized deployment
- **Minimal Frontend** - Clean, responsive login interface

## How It Works

```
┌─────────────┐     ┌─────────────┐     ┌──────────────────┐
│   Browser   │────▶│   NGINX     │────▶│  Your App        │
│             │     │  (JWT Auth) │     │  (Protected)     │
└─────────────┘     └──────┬──────┘     └──────────────────┘
                          │
                          │ No valid JWT?
                          │ Redirect to auth
                          ▼
                   ┌──────────────────┐
                   │  Auth Gateway    │
                   │  (This Project)  │
                   │                  │
                   │  1. Google OAuth │
                   │  2. Check Subset │
                   │  3. Generate JWT │
                   │  4. Set Cookie   │
                   │  5. Redirect     │
                   └──────────────────┘
```

1. User visits `app.example.com`
2. NGINX checks for valid JWT in cookie
3. If no valid JWT, redirects to `auth.example.com?return_url=https://app.example.com`
4. Auth Gateway checks if user is logged in
5. If not logged in, shows Google OAuth login page
6. After login, checks if email belongs to any configured subset
7. If authorized, generates JWT(s) and sets cookie(s) based on subset config
8. Redirects user back to original `return_url`

## Quick Start

### Prerequisites

- Node.js 18+ or Docker
- Google OAuth credentials
- NGINX with [ngx-http-auth-jwt-module](https://github.com/TeslaGov/ngx-http-auth-jwt-module)

### 1. Clone and Configure

```bash
git clone https://github.com/w453y/ngx-http-auth-jwt-gateway.git
cd ngx-http-auth-jwt-gateway

# Copy example environment file
cp .env.example .env

# Edit .env with your configuration
nano .env
```

### 2. Configure Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a new OAuth 2.0 Client ID
3. Set authorized redirect URI to: `http://your-auth-domain.com/auth/google/callback`
4. Copy Client ID and Secret to `.env`

### 3. Configure User Subsets

Edit `.env` to define your user groups:

```env
# Define subset names
SUBSETS=A,B,C

# Emails for each subset
SUBSET_A_EMAILS=admin1@company.com,admin2@company.com
SUBSET_B_EMAILS=user1@company.com,user2@company.com,user3@company.com
SUBSET_C_EMAILS=guest@external.com

# Cookies for each subset
SUBSET_A_COOKIES=auth-token,admin-token
SUBSET_B_COOKIES=auth-token
SUBSET_C_COOKIES=guest-token
```

### 4. Configure JWT Cookies

```env
# Secret for auth-token (use underscores instead of hyphens)
JWT_SECRET_auth_token=your-secret-key-here
JWT_ALGORITHM_auth_token=HS256
JWT_EXPIRES_auth_token=24h
JWT_DOMAIN_auth_token=.example.com

# Secret for admin-token
JWT_SECRET_admin_token=another-secret-key
JWT_ALGORITHM_admin_token=HS256
JWT_EXPIRES_admin_token=4h
JWT_DOMAIN_admin_token=.example.com
JWT_CLAIMS_admin_token=role:admin
```

### 5. Run with Docker

```bash
docker compose up -d
```

Or run directly:

```bash
npm install
npm start
```

### 6. Configure NGINX

See `nginx/nginx.conf.example` for a complete configuration example.

Basic NGINX configuration:

```nginx
load_module /usr/lib64/nginx/modules/ngx_http_auth_jwt_module.so;

http {
    # JWT settings
    auth_jwt_key 'your-hex-encoded-secret';  # Same as JWT_SECRET_auth_token
    auth_jwt_algorithm HS256;
    auth_jwt_location 'COOKIE=auth-token';
    auth_jwt_redirect on;
    auth_jwt_loginurl 'https://auth.example.com';

    server {
        listen 80;
        server_name app.example.com;
        
        auth_jwt_enabled on;

        location / {
            proxy_pass http://your-app:8080;
        }
    }
}
```

## Environment Variables

### Server Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server port | `3000` |
| `NODE_ENV` | Environment (development/production) | `development` |
| `SESSION_SECRET` | Express session secret | Required |

### Google OAuth

| Variable | Description | Default |
|----------|-------------|---------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | Required |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | Required |
| `GOOGLE_CALLBACK_URL` | OAuth callback URL | `/auth/google/callback` |

### Subset Configuration

| Variable | Description | Example |
|----------|-------------|---------|
| `SUBSETS` | Comma-separated subset names | `A,B,C` |
| `SUBSET_{name}_EMAILS` | Emails for subset | `user1@example.com,user2@example.com` |
| `SUBSET_{name}_COOKIES` | Cookies for subset | `auth-token,admin-token` |

### JWT Cookie Configuration

Replace `{cookie}` with cookie name using underscores (e.g., `auth_token` for `auth-token`):

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_SECRET_{cookie}` | JWT signing secret | `JWT_DEFAULT_SECRET` |
| `JWT_ALGORITHM_{cookie}` | JWT algorithm (HS256, RS256, etc.) | `HS256` |
| `JWT_EXPIRES_{cookie}` | JWT expiration | `24h` |
| `JWT_DOMAIN_{cookie}` | Cookie domain | None |
| `JWT_PATH_{cookie}` | Cookie path | `/` |
| `JWT_HTTPONLY_{cookie}` | HttpOnly flag | `true` |
| `JWT_MAXAGE_{cookie}` | Cookie max age (ms) | `86400000` |
| `JWT_SAMESITE_{cookie}` | SameSite attribute | `lax` |
| `JWT_CLAIMS_{cookie}` | Additional claims (key:value,key2:value2) | None |

### Default JWT Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `JWT_DEFAULT_SECRET` | Default secret if cookie-specific not set | Required |
| `JWT_DEFAULT_ALGORITHM` | Default algorithm | `HS256` |
| `JWT_DEFAULT_EXPIRES` | Default expiration | `24h` |
| `JWT_DEFAULT_DOMAIN` | Default cookie domain | None |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Login page |
| `/login` | GET | Login page (alias) |
| `/auth/google` | GET | Initiate Google OAuth |
| `/auth/google/callback` | GET | OAuth callback |
| `/process-auth` | GET | Process authentication and set cookies |
| `/try-different-account` | GET | Login with different Google account |
| `/logout` | GET | Logout and clear cookies |
| `/health` | GET | Health check endpoint |

## JWT Token Payload

Generated JWT tokens include:

```json
{
  "sub": "google-user-id",
  "email": "user@example.com",
  "name": "User Name",
  "subset": "A",
  ...additionalClaims,
  "iat": 1234567890,
  "exp": 1234567890
}
```

## Generating Secrets

For HMAC algorithms (HS256, HS384, HS512), generate a hex-encoded secret:

```bash
# Generate 256-bit key (for HS256)
openssl rand -hex 32

# Generate 384-bit key (for HS384)
openssl rand -hex 48

# Generate 512-bit key (for HS512)
openssl rand -hex 64
```

The same secret should be used in both:
- Auth Gateway: `JWT_SECRET_auth_token` in `.env`
- NGINX: `auth_jwt_key` directive (hex-encoded)

## Docker Deployment

### Using Docker Compose

```bash
# Build and start
docker compose up -d

# View logs
docker compose logs -f auth-gateway

# Stop
docker compose down
```

### Using Docker directly

```bash
# Build
docker build -t auth-jwt-gateway .

# Run
docker run -d \
  --name auth-gateway \
  -p 3000:3000 \
  --env-file .env \
  auth-jwt-gateway
```

## Security Considerations

1. **Use Strong Secrets**: Generate cryptographically secure secrets for JWT signing
2. **HTTPS Required**: Always use HTTPS in production for cookie security
3. **Cookie Domain**: Set appropriate cookie domain to limit scope
4. **HttpOnly Cookies**: Keep `JWT_HTTPONLY` enabled to prevent XSS attacks
5. **SameSite Attribute**: Use `strict` or `lax` to prevent CSRF attacks
6. **Session Secret**: Use a strong, unique session secret

## Troubleshooting

### Common Issues

1. **"This email is not authorized"**
   - Ensure the email is added to one of the `SUBSET_{name}_EMAILS` variables
   - Email matching is case-insensitive

2. **Cookie not being set**
   - Check `JWT_DOMAIN` matches your domain
   - Ensure you're using HTTPS in production
   - Check browser developer tools for cookie errors

3. **NGINX returning 401**
   - Verify JWT secret matches between auth gateway and NGINX
   - Check JWT algorithm matches
   - Ensure cookie name matches `auth_jwt_location`

4. **Return URL not working**
   - Ensure the return_url parameter is being passed correctly
   - Check that the URL is properly encoded

## License

MIT

## Related Projects

- [ngx-http-auth-jwt-module](https://github.com/TeslaGov/ngx-http-auth-jwt-module) - NGINX JWT authentication module
- [libjwt](https://github.com/benmcollins/libjwt) - JWT C Library