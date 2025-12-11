# Squawk DNS Manager Frontend

React TypeScript frontend for Squawk DNS Manager control plane.

## Features

- **Material-UI Design System** - Navy blue, dark grey, and gold color scheme
- **Real-time Dashboard** - DNS server fleet monitoring and query analytics
- **User Management** - Create and manage users with role-based access control
- **Team Management** - Organize users into teams for DNS zone access
- **DNS Server Fleet** - Register and monitor DNS servers with live status
- **DNS Zone Management** - Create and manage DNS zones with visibility controls
- **Analytics** - Query performance and usage analytics
- **JWT Authentication** - Secure authentication with automatic token refresh

## Tech Stack

- React 18
- TypeScript
- Material-UI (MUI) v5
- React Router v6
- Zustand (state management)
- Axios (HTTP client)
- Recharts (data visualization)
- Vite (build tool)

## Color Scheme

- **Primary (Navy)**: #2C3E71
- **Secondary (Dark Grey)**: #34495E, #2C3E50
- **Text (Gold)**: #FFD700, #FFC700
- **Background**: #1a1a1a

## Development

### Prerequisites

- Node.js 20+
- npm or yarn

### Setup

```bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Start development server
npm run dev
```

The app will be available at http://localhost:3000

### Environment Variables

Create a `.env` file:

```env
VITE_API_URL=http://localhost:5000
```

## Build

```bash
# Build for production
npm run build

# Preview production build
npm run preview
```

## Docker

### Build Image

```bash
docker build -t squawk-manager-frontend .
```

### Run Container

```bash
docker run -d \
  -p 3000:3000 \
  --name squawk-frontend \
  squawk-manager-frontend
```

### Docker Compose

```yaml
version: '3.8'
services:
  frontend:
    build: .
    ports:
      - "3000:3000"
    environment:
      - VITE_API_URL=http://backend:5000
    depends_on:
      - backend
```

## Project Structure

```
src/
├── components/
│   ├── Dashboard/       # Dashboard components
│   ├── Layout/          # Layout components (Navbar, Sidebar)
│   └── Management/      # Management components (Users, Teams, etc.)
├── hooks/               # Custom React hooks
├── pages/               # Page components
├── services/            # API client
├── styles/              # Theme configuration
├── types/               # TypeScript types
├── App.tsx              # Main app component
└── main.tsx             # Entry point
```

## Features

### Dashboard
- Real-time DNS server fleet status
- Query statistics and cache hit rates
- Query timeline chart with 24-hour history

### User Management
- Create, edit, delete users
- Assign global roles (User, OrgAdmin, UserManager, SystemAdmin)
- Permission-based UI rendering

### Team Management
- Create and manage teams
- View team member counts

### DNS Server Fleet
- Register new DNS servers with join keys
- Real-time heartbeat monitoring
- Server status indicators (online/offline/degraded)

### DNS Zone Management
- Create DNS zones with team assignment
- Set visibility levels (PUBLIC, INTERNAL, RESTRICTED, PRIVATE)
- Manage DNS records per zone

### Analytics
- Query timeline visualization
- Performance metrics
- Domain and record type analytics (coming soon)

## Authentication

The app uses JWT-based authentication with automatic token refresh:

1. User logs in with username/password
2. Backend returns access token (short-lived) and refresh token (long-lived)
3. Access token is included in all API requests
4. On 401 response, app automatically refreshes access token
5. If refresh fails, user is redirected to login

## Permissions

Role-based permissions control UI visibility:

- **User**: Basic access to assigned teams and zones
- **OrgAdmin**: Manage teams and team members
- **UserManager**: Manage users and roles
- **SystemAdmin**: Full access to all features

## License

Copyright Penguin Technologies - All Rights Reserved
