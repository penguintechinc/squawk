# Squawk DNS Website

Official website for Squawk DNS - Secure DNS-over-HTTPS System with Enterprise Authentication.

## Features

- **Marketing Site**: Complete product information and features
- **Pricing Pages**: Open Source, Premium ($5/user/month), and Embedding licenses  
- **Sales Integration**: Direct mailto links to sales@penguincloud.io
- **Documentation**: Integrated release notes and guides
- **Enterprise Solutions**: Dedicated enterprise and embedding license pages
- **Download Center**: All binaries, Docker images, and source code links

## Quick Start

### Development
```bash
cd website
npm install
npm run dev
```

### Production
```bash
cd website
npm install
npm start
```

## Environment Variables

- `PORT`: Server port (default: 3000)
- `NODE_ENV`: Environment (development/production)

## Structure

```
website/
├── server.js              # Express server
├── package.json           # Dependencies
├── views/                 # EJS templates
│   ├── layout.ejs         # Base layout
│   ├── index.ejs          # Homepage
│   ├── features.ejs       # Features page
│   ├── pricing.ejs        # Pricing page ($5/user/month)
│   ├── enterprise.ejs     # Enterprise solutions
│   ├── download.ejs       # Download center
│   ├── documentation.ejs  # Documentation hub
│   ├── contact.ejs        # Contact page
│   ├── 404.ejs           # 404 error page
│   └── 500.ejs           # 500 error page
└── public/                # Static assets
    ├── css/style.css      # Custom styles
    ├── js/main.js         # JavaScript functionality
    └── images/            # Images and assets
```

## Key Pages

### Pricing
- **Open Source**: Free AGPL v3 license
- **Premium**: $5/user/month commercial license with advanced features
- **Embedding**: Custom pricing for white-label/OEM licensing

### Sales Contact
All sales inquiries direct to: sales@penguincloud.io

### Documentation
- Integrated with GitHub repository documentation
- Dynamic release notes from `/docs/RELEASE_NOTES.md`
- Links to comprehensive guides and API references

### Enterprise
- Custom solutions for large organizations
- Implementation timeline and process
- Use cases for healthcare, financial services, MSPs

## Technologies

- **Backend**: Node.js with Express
- **Templates**: EJS templating engine
- **Frontend**: Bootstrap 5, Font Awesome
- **Security**: Helmet, rate limiting, compression
- **Syntax Highlighting**: Highlight.js for code examples

## Deployment

### Docker
```bash
# Build image
docker build -t squawk-dns-website .

# Run container
docker run -p 3000:3000 squawk-dns-website
```

### PM2 (Production)
```bash
npm install -g pm2
pm2 start server.js --name "squawk-website"
pm2 save
pm2 startup
```

### Nginx Proxy
```nginx
server {
    listen 80;
    server_name docs.squawkdns.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Features

### Security
- Helmet.js for security headers
- Rate limiting (100 requests per 15 minutes)
- Input sanitization and validation
- Content Security Policy

### Performance  
- Gzip compression
- Static asset optimization
- Efficient template rendering
- Responsive design

### SEO & Analytics
- Semantic HTML structure
- Open Graph meta tags
- Structured data markup
- Google Analytics ready

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes to website files
4. Test locally with `npm run dev`
5. Submit pull request

## License

This website is part of the Squawk DNS project and follows the same AGPL v3 license.